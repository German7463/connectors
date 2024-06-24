from datetime import datetime
import urllib.request
from lib.internal_enrichment import InternalEnrichmentConnector
import os
import yaml
import re
import urllib
import json
from stix2 import Bundle, Relationship, Indicator

from pycti import OpenCTIConnectorHelper, get_config_variable

class VysionIE(InternalEnrichmentConnector):

    def __init__(self):

        try:
            # Instantiate the connector helper from config
            config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
            config = (
                yaml.load(open(config_file_path), Loader=yaml.FullLoader)
                if os.path.isfile(config_file_path)
                else {}
            )
            self.opencti_url = get_config_variable(
                "OPENCTI_URL", ["opencti", "url"], config
            )
            self.opencti_token = get_config_variable(
                "OPENCTI_TOKEN", ["opencti", "token"], config
            )

            self.vysion_api_url = get_config_variable(
                "VYSION_API_URL", ["vysion", "api_url"], config
            )
            self.vysion_api_key = get_config_variable(
                "VYSION_API_KEY", ["vysion", "api_key"], config
            )
            self.helper = OpenCTIConnectorHelper(config, True)

            self.max_tlp = 'TLP:GREEN'
            
            self.whitelist_label = self.helper.api.label.read_or_create_unchecked(
                value="whitelist", color="#4caf50"
            )

            if self.whitelist_label is None:
                raise ValueError(
                    "The whitelist label could not be created. If your connector does not have the permission to create labels, please create it manually before launching"
                )
            
        except FileNotFoundError:
            print("Config file not found. Please check the path and try again.")
        except yaml.YAMLError as e:
            print(f"Error parsing YAML file: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def find_field_in_json(self, json_obj, field_name):
        # Si el objeto es un diccionario, busca el campo directamente o de forma recursiva en sus valores
        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                if key == field_name:
                    return value
                elif isinstance(value, (dict, list)):
                    result = self.find_field_in_json(value, field_name)
                    if result is not None:
                        return result
        # Si el objeto es una lista, busca de forma recursiva en cada elemento
        elif isinstance(json_obj, list):
            for item in json_obj:
                result = self.find_field_in_json(item, field_name)
                if result is not None:
                    return result
        # Si el campo no se encuentra, devuelve None
        return None

    def request_vysion_api(self, stix_object, type):

        if type == "email":
            endpoint = "email/"
        elif type == "url":
            endpoint = "url/"
        elif type == "BTC":
            endpoint = "btc/"
        elif type == "ETH":
            endpoint = "eth/"
        elif type == "XMR":
            endpoint = "xmr/"
        else:
            print("Invalid type")


        request = urllib.request.Request(self.api_url + "/api/v1/" + endpoint + stix_object)        
        request.add_header('Accept', 'application/json')
        request.add_header('x-api-key', self.api_key)
        request.add_header('User-Agent', "Mozilla/5.0")

        try:
            response = urllib.request.urlopen(request)
            response_data = response.read()
            data_json = json.loads(response_data)
            return data_json
        except Exception as e:
            self.helper.log_error(f"Error while calling Vysion API: {e}")
            return None
        
    def identify_crypto_wallet(self, address):
        # Bitcoin
        if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', address) or re.match(r'^bc1[qz][a-z0-9]{39,59}$', address):
            return "BTC"
        # Monero
        elif re.match(r'^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$', address):
            return "XMR"
        # Ethereum
        elif re.match(r'^0x[a-fA-F0-9]{40}$', address):
            return "ETH"
        else:
            return "Unknown"
        
    def process_stix_object(self, data, type):
        stix_obj = data["stix_objects"]
        time_now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        object_value = self.find_field_in_json(stix_obj, "value")

        if type == "cryptocurrency":

            type = self.identify_crypto_wallet(object_value)

            if type == "Unknown":
                self.helper.log_error(f"Invalid cryptocurrency wallet address: {object_value}")
                return None

        vysion_data = self.request_vysion_api(str(object_value), type)

        vysion_hits = vysion_data['data']['hits']

        for hit in vysion_hits:

            data_hit = hit['page'] 

            try:
                tag = data_hit['tag']['value'] + ", Vysion"
            except:
                tag = "Vysion"

            url = data_hit['url']['protocol'] + "://" + data_hit['url']['domain'] + data_hit['url']['path']

            # Crear un indicador STIX2 con la información extraída
            url_indicator = Indicator(
                created=str(time_now),
                modified=str(time_now),
                name=f"{url} - Vysion {type} Enriched Data",
                description=f"Enriched data from Vysion for URL Indicator ({str(object_value)}). URL: {url}, Title: {data_hit['title']}",
                pattern=f"[url:value = '{url}']",
                pattern_type="stix",
                valid_from=datetime.strptime(data_hit['date'] + 'Z', '%Y-%m-%dT%H:%M:%S.%fZ'),
                labels=[tag],
                external_references=[{
                    "source_name": "Vysion",
                    "description": "Vysion Enrichment",
                    "url": "app.vysion.ai"
                }],
            )

            relation = Relationship(
                source_ref=data["enrichment_entity"]["standard_id"],
                target_ref=url_indicator.id,
                relationship_type="related-to",
            )

            # Crear un Bundle STIX2
            bundle = Bundle(objects=[url_indicator, relation])

            # Envia el Bundle a OpenCTI
            self.helper.send_stix2_bundle(bundle.serialize())

        return 0

    def _process_message(self, data):
        opencti_entity = data["enrichment_entity"]

        # TLP de tipo GREEN por defecto
        tlp = "TLP:GREEN"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        
        self.helper.log_debug(
            "[ByronLabs] enrichment module starting: {"
            + opencti_entity["observable_value"]
            + "}"
        )

        match opencti_entity["entity_type"]:
            case "Url":
                self.process_stix_object(data, "url")
            case "Email-Addr":
                self.process_stix_object(data, "email")
            case "Cryptocurrency-Wallet":
                self.process_stix_object(data, "cryptocurrency")
            

        entity_id = data["entity_id"]
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the enrichment of entity ID {entity_id}: {data}"
        )

        self.helper.log_debug("Updating OpenCTI score...")
        self.helper.api.stix_cyber_observable.update_field(
            id=entity_id,
            input={
                "key": "x_opencti_score",
                "value": "80",
            },
        )

        # Add labels
        self.helper.log_debug("Adding labels to the cyberobservable...")
        self.helper.api.stix_cyber_observable.add_label(id=entity_id, label_name="vysion")
        self.helper.api.stix_cyber_observable.add_label(
            id=entity_id, label_name="darknet"
        )

        # Add an external reference using OpenCTI API
        self.helper.log_debug("Adding external reference...")
        external_reference = self.helper.api.external_reference.create(
            source_name="Byron Labs",
            url="https://github.com/ByronLabs/vysion-cti",
            description="A sample external reference used by the connector.",
        )

        self.helper.api.stix_cyber_observable.add_external_reference(
            id=entity_id, external_reference_id=external_reference["id"]
        )


    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    connector = VysionIE()
    connector.start()
