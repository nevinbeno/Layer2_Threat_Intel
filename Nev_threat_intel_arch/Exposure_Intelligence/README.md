# EXPOSURE INTELLIGENCE: at a glance
_______
### EXPOSURE INTELLIGENCE: Layer 1 output to layer 2 input

<div align="center">
Layer 1 output .json<br>|<br>↓<br>{Extract necessary inputs for Exposure Intelligence}<br> => [Pulbic_ip, port, product, service, OS, detailed location specifications as per our plan]<br>
|<br>|<br>↓<br>Exposure Intelligence Input<br>
</div>

_______
### EXPOSURE INTELLIGENCE: Internal Workflow

<div align = "center">
Input to the scan<br>↓<br>Conducting the Scan<br>↓<br>Obtaining the json output<br>↓<br>Save to map
</div>

_____
### EXPOSURE INTELLIGENCE: Folder Architecture
```bash
Exposure_Intelligence/
├── shdn_py/
|   ├── README.md
|   ├── fetch_data.py
|   ├── scan.py
|   ├── save_to_json.py
|   ├── save_as_map.py
|   └── pipeline.py # the execution controller
|
├── shdn_json/ # Automated Creation, never pushed
|   └── # will contain the .json files with proper names
|
└── shodan_maps/ # Automated Creation
    └── # will contain the .html files with proper names
```

_____
## Please note: 
- In the current flow, the input is taken from user, but in the project, the input will be extracted from the output json file. 
- Proper validations, `try-catch` blocks, exceptions, and many things will be added, as we plan. 