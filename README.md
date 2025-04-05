# TTP Mapper: Bridging CTI and MDR

TTP Mapper is a tool designed to integrate Tactics, Techniques, and Procedures (TTPs) from Cyber Threat Intelligence (CTI) with incident data from Managed Detection and Response (MDR) solutions. It pulls TTPs associated with malware or threat actors from a CTI Threat Intelligence Platform (TIP)—in this case, OpenCTI—and maps them to TTPs derived from true positive incidents in an MDR system. This enables security teams to correlate threat intelligence with real-world incident data for enhanced threat hunting, response, and mitigation.

#### keyword-mapping: entity = [malware, vulnerability, threat actor]

## Features
- **CTI Integration**: Extracts TTPs from OpenCTI for specified malware or threat actors.
- **MDR TTP Mapping**: Aligns CTI TTPs with TTPs identified in true positive MDR incidents.
- **Customizable**: Supports configuration for different MDR platforms and TTP frameworks (e.g., MITRE ATT&CK).
- **Output**: Generates structured mappings in formats like JSON for analysis or integration with other tools.
- **Other Output files**: BarChart for most active Entity(s).

## Use Case
- **Threat Hunting**: Identify overlaps between known threat actor behaviors and active incidents.
- **Incident Enrichment**: Augment MDR incidents with contextual CTI data.
- **Reporting**: Provide actionable insights for security analysts and leadership.

### Future Works
1. Weekly Risk-rating generation

## Prerequisites
- Python 3.9+
- Access to an OpenCTI instance (API token required)
- MDR solution with accessible TTP data (e.g., via API or export)
- Dependencies listed in `requirements.txt`

## Installation
1. Clone the repository:
 ```bash
 git clone https://github.com/vinayakcyber/TTP-Mapper.git
 cd ./TTP-Mapper/src
 ```

2. Install dependencies(Preferrably in Virtualenv):
```bash
pip install -r requirements.txt
```

3. Configure environment variables (see ).
   Configuration
   Create a .env file in the root directory with the following variables:

```plaintext
OPENCTI_URL=https://your-opencti-instance.com
OPENCTI_TOKEN=your-api-token
MDR_API_URL=https://your-mdr-api-endpoint.com
MDR_API_KEY=your-mdr-api-key
OUTPUT_FORMAT=json  # Options: json, csv
```
Alternatively, modify config.yaml with your settings.

### Usage
Run the tool with the following command:
```bash
python ttp_mapper.py <entity-type> <duration> <duration-length> <top-entities>
```
- \<entity-type\>: (provide integer value) :> 1 : "Vulnerability", 2 : "Malware", 3 : "Threat Actors.
- \<duration\>: (provide string value) :> "day", "week", "month", "quarter", "year"
- \<duration-length\>: (provide integer value) :> Example: 1, 2, 3... for quarter: 1 quarter = past 3 months
- \<top-entities\>: How many top Entities to consider for correlation? (provide integer value)

Example output:

```json
{
  "malware": "Emotet",
  "mapped_ttps": [
    {
      "cti_ttp": "T1566.001",
      "mdr_ttp": "T1566.001",
      "description": "Phishing: Spearphishing Attachment",
      "incidents": ["INC-2025-001"]
    }
  ]
}
```

### How It Works
1. **CTI Data Retrieval**: When a new report/feed gets added to the TIP and once it has TTPs and Entities mapped to it. Basically it queries OpenCTI for TTPs linked to the specified malware/threat actor.
2. **MDR Data Ingestion**: Pulls TTPs from NOT false positive incidents in the MDR system.
   _NOTE_: Thing to consider, when getting data from MDR, their can be PRE-EMPTIVE or POST blocks or Preventions, so it depends on the data that is fed into, through the (mdr_handler)[mdr_handler.py] file.
3. **TTP Mapping**: Matches CTI TTPs to MDR TTPs based on MITRE ATT&CK or custom frameworks.
4. **Result**: When Mapping is done, if a technique is more active, its score will be higher(MITRE ATTACK scoring), and can help to find the holes in the environment.
5. **Output Generation**: Produces a report of mapped TTPs with incident references.

### Contributing
Contributions are welcome! Please:

1. Fork the repository.
2. Create a feature branch (git checkout -b feature/your-feature).
3. Commit your changes (git commit -m "Add your feature").
4. Push to the branch (git push origin feature/your-feature).
5. Open a pull request.

### License
This project is licensed under the Apache License 2.0 License. See the  file for details.

### Acknowledgments
- Built with support from the OpenCTI community.
- Inspired by the need to bridge CTI and MDR workflows.

```text
This README assumes a Python-based tool and provides a clear structure for users to understand, install, and use your code. Feel free to adjust the specifics (e.g., repo URL, additional flags, or framework details) based on your actual implementation!
```
   
