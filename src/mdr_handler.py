import ssl
import warnings

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.ssl_ import create_urllib3_context

warnings.simplefilter('ignore', InsecureRequestWarning)


# Custom SSL adapter
class SSLAdapter(HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super().proxy_manager_for(*args, **kwargs)


class mdrHandler:
    def __init__(self, mdr_api_key, mdr_api_url) -> None:
        self.API_TOKEN = mdr_api_key
        self.API_URL = mdr_api_url

        # headers for the API request
        self.headers = {
            'Authorization': f'ApiToken {self.API_TOKEN}',
            'Content-Type': 'application/json'
        }

        # parameters for the API request
        self.params = {
            'limit': 1000,  # Number of results to fetch, adjust as necessary
            'skip': 0
        }
        pass

    # Function to fetch malware and their indicators
    def fetch_malware_and_indicators(self, delta):
        ssl_context = create_urllib3_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        session = requests.Session()
        adapter = SSLAdapter(ssl_context=ssl_context)
        session.mount("https://", adapter)

        self.params['createdAt__gte'] = delta
        response = session.get(self.API_URL, headers=self.headers, params=self.params, verify=False)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                threats = data['data']
                malware_list = []
                techniquesUsed = []
                for threat in threats:
                    if threat.get('indicators') and len(threat.get('indicators')) > 0:
                        threatInfo = threat.get('threatInfo')
                        if threatInfo.get('analystVerdict') != 'false_positive':
                            for indicator in threat.get('indicators'):
                                for tactic in indicator.get('tactics'):
                                    for technique in tactic.get('techniques'):
                                        techniquesUsed.append(technique.get('name'))
                            malware_info = {
                                'threat_name': threatInfo.get('threatName'),
                                'analyst_verdict': threatInfo.get('analystVerdict'),
                                'indicators': threat.get('indicators'),
                            }
                            malware_list.append(malware_info)
                return malware_list, list(set(techniquesUsed))
            else:
                print("No data found in the response.")
        else:
            print(f"Failed to fetch data. Status code: {response.status_code}")
            print(f"Response: {response.text}")


handler = mdrHandler()
handler.fetch_malware_and_indicators('2024-04-24T11:01:44.034783Z')
