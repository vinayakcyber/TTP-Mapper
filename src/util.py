import json
import os
import zipfile
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
import pandas as pd
from dateutil.relativedelta import relativedelta

D = '#990000'
C = '#f8eb55'
B = '#FF9900'
A = '#a3faa3'
MALWARE_SCORE_COLOR_MAP = {0: '#00FF00', 1: D, 2: D, 3: C, 4: C, 5: B, 6: B, 7: B, 8: A, 9: A, 10: A}
THREAT_ACTOR_SCORE_COLOR_MAP = {0: '#00FF00', 1: A, 2: B, 3: C, 4: D}


class Utils:
    def __init__(self) -> None:
        self.score = {}
        self.finalPath = ""
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        pass

    def read_json(self, file_path):
        try:
            with open(file_path, 'r') as file:
                # Parse the JSON file into a Python dictionary
                data = json.load(file)
            return data
        except Exception as e:
            print(e)

    def getDate(self, filter_type, delta):
        # Get the current date
        self.current_date = datetime.now()
        if filter_type == "day":
            return (self.current_date - timedelta(days=delta)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        elif filter_type == "week":
            return (self.current_date - timedelta(weeks=delta)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        elif filter_type == "month" or filter_type == "quarter":
            if filter_type == "quarter":
                delta *= 3
            return (self.current_date - relativedelta(months=delta)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        elif filter_type == "year":
            return (self.current_date - relativedelta(year=delta)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        elif filter_type == "specific-year":
            pass

    def filterTheDataByDuration(self, filter_type, filter_value):

        if filter_type == "day":
            # Get the current date
            current_date = datetime.now()

            # Generate a list of the last seven days
            last_seven_days = [(current_date - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(filter_value)]

            for entity in self.data:
                entity_created_date = entity['modified']

                # Parse the date string, ignoring the timezone ('Z')
                parsed_date = datetime.fromisoformat(entity_created_date.replace('Z', '+00:00'))

                # Extract just the date part
                date_only = parsed_date.date()

                # date_only.date()
                if str(date_only) in last_seven_days:
                    self.filtered_data_by_duration.append(entity)

        elif filter_type == "week":
            # Get the current date
            current_date = datetime.now()

            # Generate a list of the days
            date = datetime.strptime((current_date - timedelta(weeks=filter_value)).strftime('%Y-%m-%d'),
                                     '%Y-%m-%d').date()

            # date_object = datetime.strptime(date, '%Y-%m-%d')

            for entity in self.data:
                entity_created_date = entity['modified']

                # Parse the date string, ignoring the timezone ('Z')
                parsed_date = datetime.fromisoformat(entity_created_date.replace('Z', '+00:00'))

                # Extract just the date part
                date_only = parsed_date.date()

                # date_only.date()
                if date_only >= date:
                    self.filtered_data_by_duration.append(entity)

        elif filter_type == "month" or filter_type == "quarter":
            # Get the current date
            current_date = datetime.now()

            if filter_type == "quarter":
                filter_value *= 3

            # Generate a list of the days
            date = datetime.strptime((current_date - relativedelta(months=filter_value)).strftime('%Y-%m-%d'),
                                     '%Y-%m-%d').date()

            for entity in self.data:
                entity_created_date = entity['modified']

                # Parse the date string, ignoring the timezone ('Z')
                parsed_date = datetime.fromisoformat(entity_created_date.replace('Z', '+00:00'))

                # Extract just the date part
                date_only = parsed_date.date()

                # date_only.date()
                if date_only >= date:
                    self.filtered_data_by_duration.append(entity)

        elif filter_type == "year":
            pass

        elif filter_type == "specific-year":
            pass
        pass

    def create_and_set_FinalPath_folder(self, path):
        try:
            # Create target Directory
            self.finalPath = os.path.join(self.script_dir, "outputs", path) + os.path.sep
            print(f"Final path set to: {self.finalPath}")
            os.makedirs(self.finalPath, exist_ok=True)
            print(f"Directory '{self.finalPath}' created successfully")
        except Exception as e:
            print(f"Failed to create directory '{self.finalPath}'. Error: {e}")

    def create_folder(self, path):
        try:
            # Create target Directory
            newpath = os.path.join(self.script_dir, path) + os.path.sep
            print(f"path set to: {newpath}")
            os.makedirs(newpath, exist_ok=True)
            print(f"Directory '{newpath}' created successfully")
        except Exception as e:
            print(f"Failed to create directory '{newpath}'. Error: {e}")

    def get_relevant_attack_patterns(self, helper, most_used_entity_ids, entityName, entityType):
        if entityName is not None:
            helper.log_info("Getting attack-pattern relations for {}".format(entityName))
        query = """
            query RelationshipsStixCoreRelationshipsLinesPaginationQuery(
            $fromId: [String]
            $fromTypes: [String]
            $toTypes: [String]
            $count: Int!
            $cursor: ID
            $orderBy: StixCoreRelationshipsOrdering
            $orderMode: OrderingMode
            $filters: FilterGroup
            ) {
            stixCoreRelationships(
                fromId: $fromId
                fromTypes: $fromTypes
                toTypes: $toTypes
                first: $count
                after: $cursor
                orderBy: $orderBy
                orderMode: $orderMode
                filters: $filters
            ) {
                edges {
                node {
                    id
                    to {
                    ... on StixCoreObject {
                        id
                        entity_type
                    }
                    }
                }
                }
                pageInfo {
                hasNextPage
                endCursor
                }
            }
            }

                """
        internalFilters = [
            {
                "key": "fromTypes",
                "values": ["Malware"] if entityType == 2 else ["Threat-Actor-Group", "Threat-Actor-Individual",
                                                               "Intrusion-Set"],
                "operator": "eq",
                "mode": "or"
            },
            {
                "key": "toTypes",
                "values": ["Attack-Pattern"],
                "operator": "eq",
                "mode": "or"
            },
            {
                "key": "fromId",
                "values": most_used_entity_ids if not isinstance(most_used_entity_ids, dict) else list(
                    most_used_entity_ids.keys()),
                "operator": "eq",
                "mode": "or"
            }
        ]
        if entityType == 2:
            internalFilters.append({
                "key": "createdBy",
                "values": [
                    "94f21e6a-2805-4b30-b3d6-12363bbfa0d0",
                    "cd2e2495-e81e-492a-ac51-1bf9fb3c70f4",
                    "59bb47ac-db88-4b66-ab51-14ba1b88ed86"
                ],
                "operator": "eq",
                "mode": "or"
            })

        data = helper.api.query(
            query,
            {
                "fromId": most_used_entity_ids if not isinstance(most_used_entity_ids, dict) else list(
                    most_used_entity_ids.keys()),
                "fromTypes": ["Malware"] if entityType == 2 else ["Threat-Actor-Group", "Threat-Actor-Individual",
                                                                  "Intrusion-Set"],
                "toTypes": ["Attack-Pattern"],
                "count": 10000,
                "orderBy": None,
                "filters": {
                    "mode": "and",
                    "filters": [
                        {
                            "key": "entity_type",
                            "values": ["stix-core-relationship"],
                            "operator": "eq",
                            "mode": "or"
                        }
                    ],
                    "filterGroups": [
                        {
                            "mode": "and",
                            "filters": internalFilters,
                            "filterGroups": []
                        }
                    ]
                }
            }
        )

        attack_pattern_ids = [dat.get('node').get('to').get('id') for dat in
                              data['data']['stixCoreRelationships']['edges'] if
                              dat.get('node').get('to').get('entity_type') == 'Attack-Pattern']

        if len(attack_pattern_ids) == 0:
            return []

        _filters = {
            "mode": "and",
            "filters": [{"key": "id", "values": attack_pattern_ids}],
            "filterGroups": [],
        }
        attack_patthern_data = helper.api.attack_pattern.list(filters=_filters)
        return list(set([str(dat.get('x_mitre_id')) for dat in attack_patthern_data if
                         dat.get('x_mitre_id') and len(str(dat.get('x_mitre_id')).strip()) > 0]))

    def get_relevant_malwares(self, helper, most_used_entity_ids, entityName, entityType):
        if entityName is not None:
            helper.log_info("Getting Malware relations for {}".format(entityName))
        query = """
            query RelationshipsStixCoreRelationshipsLinesPaginationQuery(
            $fromId: [String]
            $fromTypes: [String]
            $toTypes: [String]
            $count: Int!
            $cursor: ID
            $orderBy: StixCoreRelationshipsOrdering
            $orderMode: OrderingMode
            $filters: FilterGroup
            ) {
            stixCoreRelationships(
                fromId: $fromId
                fromTypes: $fromTypes
                toTypes: $toTypes
                first: $count
                after: $cursor
                orderBy: $orderBy
                orderMode: $orderMode
                filters: $filters
            ) {
                edges {
                node {
                    id
                    from {
                    ... on StixCoreObject {
                        id
                    }
                    }
                    to {
                    ... on StixCoreObject {
                        id
                        entity_type
                    }
                    }
                }
                }
                pageInfo {
                hasNextPage
                endCursor
                }
            }
            }

                """
        internalFilters = [
            {
                "key": "fromTypes",
                "values": ["Malware"] if entityType == 2 else ["Threat-Actor-Group", "Threat-Actor-Individual",
                                                               "Intrusion-Set"],
                "operator": "eq",
                "mode": "or"
            },
            {
                "key": "toTypes",
                "values": ["Malware"],
                "operator": "eq",
                "mode": "or"
            },
            {
                "key": "fromId",
                "values": most_used_entity_ids if not isinstance(most_used_entity_ids, dict) else list(
                    most_used_entity_ids.keys()),
                "operator": "eq",
                "mode": "or"
            }
        ]
        if entityType == 2:
            internalFilters.append({
                "key": "createdBy",
                "values": [
                    "94f21e6a-2805-4b30-b3d6-12363bbfa0d0",
                    "cd2e2495-e81e-492a-ac51-1bf9fb3c70f4",
                    "59bb47ac-db88-4b66-ab51-14ba1b88ed86"
                ],
                "operator": "eq",
                "mode": "or"
            })

        data = helper.api.query(
            query,
            {
                "fromId": most_used_entity_ids if not isinstance(most_used_entity_ids, dict) else list(
                    most_used_entity_ids.keys()),
                "fromTypes": ["Malware"] if entityType == 2 else ["Threat-Actor-Group", "Threat-Actor-Individual",
                                                                  "Intrusion-Set"],
                "toTypes": ["Malware"],
                "count": 10000,
                "orderBy": None,
                "filters": {
                    "mode": "and",
                    "filters": [
                        {
                            "key": "entity_type",
                            "values": ["stix-core-relationship"],
                            "operator": "eq",
                            "mode": "or"
                        }
                    ],
                    "filterGroups": [
                        {
                            "mode": "and",
                            "filters": internalFilters,
                            "filterGroups": []
                        }
                    ]
                }
            }
        )

        relevant_malware_map = {}
        malware_ids = []
        for dat in data['data']['stixCoreRelationships']['edges']:
            if dat.get('node').get('to').get('entity_type') == 'Malware':
                if relevant_malware_map.get(dat.get('node').get('from').get('id')) is None:
                    linked_ids = []
                else:
                    linked_ids = relevant_malware_map.get(dat.get('node').get('from').get('id'))

                linked_ids.append(dat.get('node').get('to').get('id'))
                malware_ids.append(dat.get('node').get('to').get('id'))
                relevant_malware_map[dat.get('node').get('from').get('id')] = linked_ids

        if len(malware_ids) == 0:
            return []

        _filters = {
            "mode": "and",
            "filters": [{"key": "id", "values": malware_ids}],
            "filterGroups": [],
        }
        malware_data = helper.api.malware.list(filters=_filters)
        malware_name_map = {}
        for dat in malware_data:
            if dat.get('name') and len(str(dat.get('name')).strip()) > 0:
                malware_name_map[dat.get('id')] = dat.get('name')

        return relevant_malware_map, malware_name_map

    def create_threat_actor_to_malware_table(self, relevant_malware_map, malware_name_map, threat_actor_name_map,
                                             filename):

        final_data = {}
        for key in relevant_malware_map.keys():
            values = []
            for value in relevant_malware_map.get(key):
                values.append(malware_name_map.get(value))
            # final_values = values.strip()[:-1]
            final_data[threat_actor_name_map.get(key)] = values

        # Create a list of keys and a list of values
        keys = list(final_data.keys())
        values = [', '.join(map(str, final_data[key])) for key in keys]

        # Create a DataFrame
        df = pd.DataFrame({'Threat Actors/Intusion Sets': keys, 'Linked Malwares': values})

        # Save the DataFrame to a CSV file
        csv_file_path = self.finalPath + filename + '.csv'
        df.to_csv(csv_file_path, index=False)
        return csv_file_path

    def update_pattern_score(self, techniques):
        for technique in techniques:
            if self.score.get(technique):
                technique_score = self.score.get(technique)
                self.score[technique] = technique_score + 1
            else:
                self.score[technique] = 1

    def update_pattern_score_with_internal(self, techniques):
        for technique in techniques:
            if self.score.get(technique):
                technique_score = self.score.get(technique)
                finalScore = technique_score + 5
                if finalScore > 10:
                    finalScore = 10
                self.score[technique] = finalScore
            else:
                self.score[technique] = 5

    def generate_mitre_attack_navigator_json(self, techniques, filename, entity_type):
        if entity_type == 2:
            colors = ["#00FF00", "#a3faa3", "#a3faa3", "#a3faa3", "#f8eb55", "#f8eb55", "#FF9900", "#FF9900", "#FF9900",
                      "#990000", "#990000"]
            Fe = '#990000'
            Ee = '#f8eb55'
            De = '#FF9900'
            Ce = '#a3faa3'
            Be = 'color'
            Ae = 'label'
            legend_items = [{Ae: '0', Be: '#00FF00'}, {Ae: '1', Be: Ce}, {Ae: '2', Be: Ce}, {Ae: '3', Be: Ce},
                            {Ae: '4', Be: Ee}, {Ae: '5', Be: Ee}, {Ae: '6', Be: De}, {Ae: '7', Be: De},
                            {Ae: '8', Be: De}, {Ae: '9', Be: Fe}, {Ae: '10', Be: Fe}]

        elif entity_type == 3:
            colors = ["#00FF00", "#a3faa3", "#f8eb55", "#FF9900", "#990000"]
            Fe = '#990000'
            Ee = '#f8eb55'
            De = '#FF9900'
            Ce = '#a3faa3'
            Be = 'color'
            Ae = 'label'
            legend_items = [{Ae: '0', Be: '#00FF00'}, {Ae: '1', Be: Ce}, {Ae: '2', Be: De}, {Ae: '3', Be: Ee},
                            {Ae: '4', Be: Fe}]
        navigator_json = {
            "name": filename[:filename.lower().find('_since')],
            "versions": {
                "layer": "4.5",
                "navigator": "4.8.1",
                "attack": "15"
            },
            "domain": "enterprise-attack",
            "description": "A custom ATT&CK Navigator layer generated from a list of techniques and tactics.",
            "techniques": [],
            "gradient": {
                "colors": colors,
                "minValue": 0,
                "maxValue": 10
            },
            "legendItems": legend_items
        }

        technique_set = set(techniques)
        for technique in techniques:
            if technique.startswith('T'):
                if '.' in technique:
                    parent_technique = technique.split('.')[0]
                    show_subtechniques = parent_technique in technique_set
                else:
                    show_subtechniques = any(t.startswith(technique + '.') for t in technique_set)

                navigator_json["techniques"].append({
                    "techniqueID": technique,
                    "score": self.score.get(technique),
                    "color": MALWARE_SCORE_COLOR_MAP.get(
                        self.score.get(technique)) if entity_type == 2 else THREAT_ACTOR_SCORE_COLOR_MAP.get(
                        self.score.get(technique)),
                    "comment": "-",
                    "showSubtechniques": show_subtechniques
                })
            else:
                navigator_json["techniques"].append({
                    "techniqueID": "",
                    "tactic": technique,
                    "score": self.score.get(technique),
                    "color": MALWARE_SCORE_COLOR_MAP.get(
                        self.score.get(technique)) if entity_type == 2 else THREAT_ACTOR_SCORE_COLOR_MAP.get(
                        self.score.get(technique)),
                    "comment": "-",
                    "showSubtechniques": False
                })

        with open(self.finalPath + filename + '.json', 'w') as file:
            file.write(json.dumps(navigator_json, indent=4))

        return self.finalPath + filename + '.json'

    def create_horizontal_bar_chart(self, data, xlabel, ylabel, delta_date, filter_type):
        # Extracting keys and values from the dictionary
        keys = list(data.keys())
        values = list(data.values())

        # Creating the horizontal bar chart
        plt.figure(figsize=(10, 6))
        bars = plt.barh(keys, values, color='skyblue')
        # Adding values on the bars
        for bar in bars:
            plt.text(
                bar.get_width() - bar.get_width() / 2,  # Positioning the text slightly to the right of the bar
                bar.get_y() + bar.get_height() / 2,  # Centering the text vertically on the bar
                f'{bar.get_width()}',  # Text value
                va='center'  # Vertical alignment
            )

        # Adding labels and title
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.title('Horizontal Bar Chart')
        # Adjust layout to make room for the y-axis labels
        plt.tight_layout()

        # Saving the chart to a PDF file
        plt.savefig(
            self.finalPath + xlabel.strip().replace(" ", "_") + "_" + str(delta_date) + "_" + filter_type + ".jpg",
            format='jpg')

        return self.finalPath + xlabel.strip().replace(" ", "_") + "_" + str(delta_date) + "_" + filter_type + ".jpg"

    def create_zip_from_file_list(self, file_list, output_zip_name, filter_Value, entity, start_date, end_date):
        """
        Creates a zip file containing all files listed in file_list.

        Args:
            file_list (list): List of file paths to include in the zip file.
            output_zip_path (str): Path to the output zip file.
        """
        output_zip_path = self.script_dir + "/outputs/" + output_zip_name + "_" + datetime.strptime(start_date,
                                                                                                    "%Y-%m-%dT%H:%M:%S.%fZ").strftime(
            "%B-%d-%Y") + "_to_" + end_date.strftime("%B-%d-%Y") + ".zip"
        zip_check = False
        with zipfile.ZipFile(output_zip_path, 'w') as zipf:
            for file in file_list:
                if os.path.isfile(file):
                    zipf.write(file, os.path.basename(file))
                    zip_check = True
                else:
                    print(f"File not found: {file}")

            # Delete the files after creating the zip
        for file in file_list:
            if os.path.isfile(file):
                os.remove(file)
            else:
                print(f"File not found for deletion: {file}")
