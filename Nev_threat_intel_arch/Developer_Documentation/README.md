# Threat Intelligence: $Developer$ $Documentation$

### For the attention of readers
>   This document explains how to set up, configure, and run **Layer-2: Threat Intelligence of the platform**.
It is intended for developers who want to run the project locally, understand integrations, or extend intelligence sources.

## Pre — requesites
- OS (Windows / Linux Ubuntu)
- Python software, and pip installation manager [Install Python]()
- VS Code (Visual Studio Code) [Install VS Code]()
- Internet Connection
- Git
## Layer 2 Architecture
<!-- to be implemented -->
## Set up
1. Clone the repo, and get inside it
    ```bash
    > git clone repoName
    > cd repoName
    ```
2. [Virtual Environment Setup](CreateVirtualEnv.md)
3. Install all the libraries and packages inside the virtual environment. 
    ```bash
    > pip install -r requirements.txt
    ```
4. API setup<br>
    4.1 [Shodan API setup](APIs/Shodan_API_setup.md)<br>
    4.2 [VirusTotal API setup](APIs/VirusTotal_API_setup.md)<br>
    4.3 [NVD API setup](APIs/NVD_API_key.md)<br>
    4.4 [Vulners API setup](APIs/Vulners_API__setup.md)<br>
5. [Output Architecture: From layer 2 to upper layers](Output_Architecture.md)<br>
6. [Troubleshooting](troubleshooting.md)