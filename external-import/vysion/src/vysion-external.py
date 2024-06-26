# import os
import sys
import time

from stix2 import Bundle, ThreatActor, Relationship, Incident, Identity
from lib.external_import import ExternalImportConnector
import os
import yaml
import urllib
import json
from pycti import OpenCTIConnectorHelper, get_config_variable


class VysionEI(ExternalImportConnector):
    """Vysion External Import Connector"""

    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.SafeLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

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
        

    def get_interval(self) -> int:
        return int(self.template_interval) * 60 * 60 * 24

    def call_vysion_api_feed(self):

        request = urllib.request.Request(
            self.vysion_api_url + "/api/v1/feed/ransomware"
        )
        request.add_header("Accept", "application/json")
        request.add_header("x-api-key", self.vysion_api_key)
        request.add_header("User-Agent", "Mozilla/5.0")

        try:
            response = urllib.request.urlopen(request)
            response_data = response.read()
            data_json = json.loads(response_data)
            return data_json
        except Exception as e:
            self.helper.log_error(f"Error while calling Vysion API: {e}")
            return None

    def get_feed_vysion(self):

        data = self.call_vysion_api_feed()

        events = []

        for event in data["data"]["hits"]:
            company = event.get("company", "")
            company_link = event.get("company_link", "")
            link_post = event.get("link_post", "")
            ransomware_group = event.get("group", "")
            date = event.get("date", "")
            info = event.get("info", "")
            victim_country = event.get("country", "")

            events.append(
                {
                    "company": company,
                    "company_link": company_link,
                    "link_post": link_post,
                    "ransomware_group": ransomware_group,
                    "date": date,
                    "info": info,
                    "victim_country": victim_country,
                }
            )

        return events

    def process_event(self, event):

        try:

            threat_actor = ThreatActor(
                name=event["ransomware_group"], labels=["ransomware"]
            )

            victim = Identity(
                name=event["company"],
                type="identity",
                identity_class="individual",
            )

            incident = Incident(
                name="Vysion Feed: "
                + event["ransomware_group"]
                + " Attack"
                + " - "
                + event["company"],
                description=event["info"],
                labels=["ransomware"],
                external_references=[
                    {
                        "source_name": "Vysion - Ransomware Feed: "
                        + event["ransomware_group"]
                        + " Attack",
                        "url": event["link_post"],
                    }
                ],
            )

            relation = Relationship(
                source_ref=incident.id,
                target_ref=threat_actor.id,
                relationship_type="attributed-to",
                description="Attribution of the incident to the threat actor",
            )

            relation2 = Relationship(
                source_ref=incident.id,
                target_ref=victim.id,
                relationship_type="targets",
                description="Victim of the incident",
            )

            # Crea un Bundle con los objetos STIX
            bundle = Bundle(objects=[threat_actor, incident, relation, relation2])

            # Envia el Bundle a OpenCTI
            self.helper.send_stix2_bundle(bundle.serialize())

        except Exception as e:
            self.helper.log_error(f"Error while processing event: {e}")

    def run(self) -> None:

        self.helper.log_info(f"{self.helper.connect_name} connector is running...")

        try:

            events = self.get_feed_vysion()
            for event in events:
                self.helper.log_info(f"Event: {event}")
                self.process_event(event)

        except Exception as e:
            self.helper.log_error(f"Error while running the connector: {e}")

        return 0


if __name__ == "__main__":
    
    try:
        connector = VysionEI()
        print("Connector created")
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
