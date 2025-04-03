import argparse
import os
from typing import Any

from dotenv import load_dotenv
from pycti import OpenCTIConnectorHelper

from mdr_handler import mdrHandler
from util import Utils

# Load variables from .env
load_dotenv()

# Now you can get them using os.getenv
OPENCTI_URL = os.getenv('OPENCTI_URL')
OPENCTI_TOKEN = os.getenv('OPENCTI_TOKEN')
MDR_API_URL = os.getenv('MDR_API_URL')
MDR_API_KEY = os.getenv('MDR_API_KEY')
LOG_LEVEL = os.getenv('LOG_LEVEL')

ENTITY_TYPE = {
    1: "Vulnerability",
    2: "Malware",
    3: "Threat Actors",
    4: "Attack Pattern"
}


class dataCollector:

    def __init__(self) -> None:

        config = {
            "opencti": {
                "url": OPENCTI_URL,
                "token": OPENCTI_TOKEN
            },
            "connector": {
                "id": "custom-ttp-mapping",
                "type": "INTERNAL_EXPORT",
                "name": "custom-reporting",
                "confidence_level": 15,  # From 0 (Unknown) to 100 (Fully trusted)
                "log_level": LOG_LEVEL
            }
        }

        self.helper = OpenCTIConnectorHelper(config=config)
        self.helper.log_info("Connected to OpenCTI ...")

        self.utils = Utils()

        self.mdrhandler = mdrHandler(MDR_API_KEY, MDR_API_URL)

        self.helper.log_info("Setup Connection props to MDR ...")

        self.data = {}  # For the data from OCTI or any other TIP
        self.filtered_data_by_duration = []  # filtered data for a specific duration
        self.entity_use_count_ids = {}  # entity-ID to Count-of-use mapping
        self.entity_use_count_names = {}  # entity-name to Count-of-use mapping
        self.most_used_entity = {}  # most-active entity
        self.most_used_entity_ids = []  # most active entity ids
        self.delta_date = None
        self.id_to_name = {}  # entity id to name conversion dict
        self.summary_dict = {}
        self.fileList = []  # Final list of files to create zip.
        self.current_date = None


    def getAllEntity(self, entity_type):
        """
        Retrieves all entities of a specified type.

        This function checks the provided integer `entity_type` to determine
        which group of entities to fetch. For example:
          - Entity Mapping:
                1: "Vulnerability",
                2: "Malware",
                3: "Threat Actors",
                4: "Attack Pattern"
          - Additional cases can be added for other entity types.

        Args:
            entity_type (int): An integer specifying the type of entities to retrieve.

        Returns:
            Any: The list or collection of retrieved entities, depending on your data structure.
        """
        if entity_type == 1:
            self.data = self.helper.api.vulnerability.list(
                first=5000,
                getAll=False,
                filterGroups=[]
            )
        elif entity_type == 2:
            self.data = self.helper.api.malware.list(
                first=5000,
                getAll=False,
                filterGroups=[]
            )
        elif entity_type == 3:
            self.data = self.helper.api.threat_actor.list(
                first=5000,
                getAll=False,
                filterGroups=[]
            ) + self.helper.api.intrusion_set.list(
                first=5000,
                getAll=False,
                filterGroups=[]
            )
        elif entity_type == 4:
            self.data = self.helper.api.attack_pattern.list(
                first=5000,
                getAll=False,
                filterGroups=[]
            )

    def _create_filter_for_reports(self, ids: list, timeType, timeDelta) -> dict[str, str | list[
        dict[str, str | list[str]] | dict[str, str | list[str]] | dict[str, str | list] | dict[str, str | list[str]]] |
                                                                                      list[Any]]:
        """
        Creates a nested filter dictionary for generating or querying the reports/feed related data.

        This function constructs a deeply nested data structure that captures
        filtering criteria based on the provided arguments.

        The nested filters are required for graphql querying

        Args:
            ids (list): A list of identifiers used to filter or group data.
            timeType: Represents a specific time-based classification or dimension
                (e.g., days, weeks, months, etc.). Used for determining how the time
                window or range is applied in the returned filter.
            timeDelta: Indicates the numeric or date-based window, offset, or range
                used for generating time-bound report filters.

        Returns:
            dict[str, str | list[dict[str, str | list[str]] | dict[str, str | list[str]] |
                                  dict[str, str | list] | dict[str, str | list[str]]] | list[Any]]:
                A dictionary representing the report filters. The structure can
                include multiple levels of nested lists and dictionaries, each
                defining specific filtering criteria for the reports.
        """

        self.delta_date = self.utils.getDate(timeType, timeDelta)
        return {
            "mode": "and",
            "filters": [{
                "key": "entity_type",
                "values": ["Report"],
                "operator": "eq",
                "mode": "or"
            },
                {
                    "key": "report_types",
                    "values": ["threat-report"],
                    "operator": "eq",
                    "mode": "or"
                },
                {
                    "key": "objects",
                    "values": ids,
                    "operator": "eq",
                    "mode": "or"
                },
                {
                    "key": "created",
                    "values": [self.delta_date],
                    "operator": "gte",
                    "mode": "or"
                }
# For Specific case, update below
                # ,
                # {
                #     "key": "objectLabel",
                #     "values": [
                #         "ec5e4f0f-8cd6-4cfa-b55c-4e42ecc36551",
                #         "ad99fec7-ed71-44b5-a3f8-57a3b0ed3998",
                #         "541d48a8-1691-4adc-8157-b381365cf25b",
                #         "7ea580ca-1eb4-4da2-9cf7-cb70176561e2"
                #     ],
                #     "operator": "eq",
                #     "mode": "or"
                # }
            ],
            "filterGroups": [],
        }

    def generate_count(self, ids, filtered_data):
        """
        updates the 'entity_use_count_ids' dict based on the provided id's and filtered data.

        Args:
            ids (list): A list of identifiers for which the counts should be generated.
            filtered_data (doct): The data (already filtered) from which the counts are computed.
        """
        for data in filtered_data:
            objects = data.get('objectsIds')
            for object in objects:
                if object in ids:
                    if self.entity_use_count_ids.get(object) is not None:
                        count = self.entity_use_count_ids.get(object)
                        count += 1
                        self.entity_use_count_ids[object] = count
                    else:
                        self.entity_use_count_ids[object] = 1

    def get_sorted_dict(self):
        # Sorting the dictionary by its values
        self.most_used_entity = dict(
            sorted(self.entity_use_count_names.items(), key=lambda item: item[1], reverse=True)[:15])
        self.most_used_entity_ids = dict(
            sorted(self.entity_use_count_ids.items(), key=lambda item: item[1], reverse=True)[:15])

    def get_entity_name(self):
        """
        updates the 'id_to_name' dict based on the provided 'entity_use_count_ids' keys.
        """
        malware_ids = self.entity_use_count_ids.keys()
        for object in self.filtered_data_by_duration:
            if object['id'] in malware_ids:
                self.entity_use_count_names[object['name']] = self.entity_use_count_ids.get(object['id'])
                self.id_to_name[object['id']] = object['name']

    def get_report_content(self, reports):
        """
        Gets the contents of the specified reports.

        Returns:
            - Content_map = report_id to content/description mapping
        """
        def find_nth_occurrence(text, substring, n):
            start = 0
            for i in range(n):
                start = text.find(substring, start) + 1
                if start == 0:
                    return -1  # Substring not found n times
            return start - 1

        def extract_text_before_nth_occurrence(text, substring, n):
            nth_occurrence_index = find_nth_occurrence(text, substring, n)
            if nth_occurrence_index == -1:
                return None  # Less than n occurrences of the substring
            return text[:nth_occurrence_index]

        content_map = {}
        query = """
            query RootReportQuery($id: String!) {
                report(id: $id) {
                    id
                    ...StixCoreObjectContent_stixCoreObject
                }
                }

                fragment StixCoreObjectContent_stixCoreObject on StixCoreObject {
                id
                ... on Report {
                    contentField: content
                }
                }
                """
        for id in reports:
            parameters = {
                "id": id
            }
            data = self.helper.api.query(query, parameters)
            if data['data']['report']['contentField'] is not None and len(data['data']['report']['contentField']) > 10:
                content_map[id] = extract_text_before_nth_occurrence(data['data']['report']['contentField'], '</p>', 7)
        return content_map

    def summarize_top_three_entities(self, ids, reports):
        report_ids = []
        for data in reports:
            objects = data.get('objectsIds')
            for object in objects:
                if object in ids:
                    report_ids.append(data.get('id'))
        content_map = self.get_report_content(report_ids)
        for data in reports:
            objects = data.get('objectsIds')
            for object in objects:
                if object in ids:
                    if self.summary_dict.get(object) is not None:
                        summary_data = self.summary_dict.get(object)
                    else:
                        self.summary_dict[object] = {}
                        summary_data = {}
                    if data.get('description') is not None and data.get(
                            'description') != 'Report an Incident  \nTalk to Sales':
                        summary_data[data.get('name')] = data.get('description') + "\n" + (
                            content_map.get(data.get('id')) if content_map.get(data.get('id')) is not None else "")
                        self.summary_dict[object] = summary_data

    def _process_request(self, args):
        entity_type = args[0]
        filter_type = args[1]
        filter_value = args[2]
        top_entity_count = args[3]

        print("Got the following parameters: Entity type: {}, Duration type: {}, Duration: {}".format(
            ENTITY_TYPE.get(entity_type), filter_type, filter_value))
        self.utils.create_and_set_FinalPath_folder(filter_type)

        # Get the data
        self.getAllEntity(entity_type=entity_type)  # get all data for this entity_type
        self.utils.filterTheDataByDuration(filter_type, filter_value)  # filter the above data by duration
        ids = [entity['id'] for entity in self.filtered_data_by_duration]  # get all opencti ids for the filtered info

        # Find the Reports for the data
        filtered_reports = self.helper.api.report.list(getAll=True, filters=self._create_filter_for_reports(ids=ids,
                                                                                                            timeType=filter_type,
                                                                                                            timeDelta=filter_value))  # find all linked reports
        self.generate_count(ids,
                            filtered_reports)  # Find the priority based on how many reports talk about a single id/entity value

        # Some information gathering
        self.get_entity_name()  # Find the all names for each id
        self.get_sorted_dict()  # Sort the output based on the count, to get priority

        # Generate the horizontal bar chart for the top 15
        self.fileList.append(self.utils.create_horizontal_bar_chart(data=self.most_used_entity,
                                                                    xlabel='Top 15 Most Active ' + ENTITY_TYPE.get(
                                                                        entity_type),
                                                                    ylabel=ENTITY_TYPE.get(entity_type),
                                                                    delta_date=self.delta_date,
                                                                    filter_type=filter_type))
        print("Generated the top15 horizontal Bar Chart for Entity type: {}".format(ENTITY_TYPE.get(entity_type)))

        if entity_type != 1:  # Since a vulnerability is not linked to any attack pattern(yet) in OCTI

            # Get attack_pattern for top 3 most active, and update there score for the mitre attack navigator
            print("Updating the score for top x")
            for entity in list(self.most_used_entity_ids.keys())[:top_entity_count]:
                self.utils.update_pattern_score(
                    self.utils.get_relevant_attack_patterns(helper=self.helper, most_used_entity_ids=[entity],
                                                            entityName=self.id_to_name.get(entity),
                                                            entityType=entity_type))
            print("Updated the score for top x")

            self.summarize_top_three_entities(list(self.most_used_entity_ids.keys())[:top_entity_count],
                                              filtered_reports)
            # self.fileList.append(self.utils.summarize_text(self.summary_dict, self.id_to_name, entity_type))

            # Get attack_pattern for all 15, and update there score for the mitre attack navigator->
            # to have a final output which is a combo like: All 15 + 1 + 2 + 3(there duplicates because 1,2,3 are already part of 15, but that helps prioritization)
            print("Getting attack patterns for top 3")
            relevant_attack_patterns = self.utils.get_relevant_attack_patterns(helper=self.helper,
                                                                               most_used_entity_ids=self.most_used_entity_ids,
                                                                               entityName=None, entityType=entity_type)
            self.utils.update_pattern_score(relevant_attack_patterns)
            print("Finalized the scores for top 3")

            # Generate the mitre attack navigator json v5.1 for above data.
            fileName = ENTITY_TYPE.get(entity_type) + "_relevant_Attack_patterns_Since_" + str(self.delta_date)[
                                                                                           :self.delta_date.lower().find(
                                                                                               '.')].replace(":", "-")
            self.fileList.append(
                self.utils.generate_mitre_attack_navigator_json(relevant_attack_patterns, fileName, entity_type))

            if entity_type == 2:  # Below we update the above navigator data, with Malware data we see in our env, i.e. MDR
                internal_malware_data, internal_malware_techniques = self.mdrhandler.fetch_malware_and_indicators(
                    delta=self.delta_date)
                self.utils.update_pattern_score_with_internal(internal_malware_techniques)
                print("Updated scores for with internal Malware data")

                fileName = ENTITY_TYPE.get(entity_type) + "_relevant_Attack_patterns_plus_Internal_Since_" + str(
                    self.delta_date)[:self.delta_date.lower().find('.')].replace(":", "-")
                self.fileList.append(self.utils.generate_mitre_attack_navigator_json(
                    list(set(internal_malware_techniques + relevant_attack_patterns)), fileName, entity_type))

            if entity_type == 3:  # Get Malwares linked with the threat actor
                relevant_malware_map, malware_data = self.utils.get_relevant_malwares(helper=self.helper,
                                                                                      most_used_entity_ids=self.most_used_entity_ids,
                                                                                      entityName=None,
                                                                                      entityType=entity_type)
                fileName = ENTITY_TYPE.get(entity_type) + "_linked_Malwares"
                self.fileList.append(
                    self.utils.create_threat_actor_to_malware_table(relevant_malware_map, malware_data, self.id_to_name,
                                                                    fileName))
        else:
            print("Can't generate Attack pattern for Entity type: {}".format(ENTITY_TYPE.get(entity_type)))

        if self.fileList is not None and len(self.fileList) > 0:
            self.utils.create_zip_from_file_list(self.fileList,
                                                 "Entity_{}_DurationType_{}_Duration_{}".format(entity_type,
                                                                                                filter_type,
                                                                                                filter_value),
                                                 filter_type, ENTITY_TYPE.get(entity_type), self.delta_date,
                                                 self.current_date)


if __name__ == "__main__":
    try:
        # if sys.argv and len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="Process requests for the collector. Requires four parameters: an integer, a string indicating time unit,  another integer, another integer."
        )
        parser.add_argument(
            'param1',
            type=int,
            help='Entity Type (provide integer value) :> 1 : "Vulnerability", 2 : "Malware", 3 : "Threat Actors"'
        )
        parser.add_argument(
            'param2',
            type=str,
            help='Duration Type (provide string value) :> "day", "week", "month", "quarter", "year"'
        )
        parser.add_argument(
            'param3',
            type=int,
            help='Duration length (provide integer value) :> Example: 1, 2, 3... for quarter: 1 quarter = past 3 months'
        )
        parser.add_argument(
            'param4',
            type=int,
            help='How many top Entities to consider for correlation? (provide integer value)'
        )

        args = parser.parse_args()

        if int(args.param1) <= 0 or int(args.param1) > 4:
            print("Wrong Input provided")
            exit(0)

        # Call the _process_request method with the provided arguments
        collector = dataCollector()  # Assuming Collector is a defined class

        collector._process_request([args.param1, args.param2, args.param3, args.param4])

    except Exception as e:
        print(e)
