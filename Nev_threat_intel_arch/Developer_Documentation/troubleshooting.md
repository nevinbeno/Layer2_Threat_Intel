# ⚠️ Troubleshooting
> This document lists common issues encountered while setting up and running **Layer 2 Threat Intelligence**, along with their causes and solutions. 

|Sl. no |Issue name|Solution|
|-----|-----------|--------|
|1.|API Key Issues|[Click Here](#1️⃣-api-key-issues)|
|2.|Network and Connectivity Related Issues|[Click Here](#2️⃣-network--connectivity-issues)|
|3.|Data Not Found / Empty Result|[Click Here](#3️⃣-data-not-found--empty-results)|
|4.|Json parsing Errors|[Click Here](#4️⃣-json-parsing-errors)|
|5.|Rate Limiting Issues|[Click Here](#5️⃣-rate-limiting-issues)|
|6.|Map / Visualization Issues (Shodan Map)|[Click Here](#6️⃣-map--visualization-issues-shodan-map)|
|7.|Environment & Dependency Issues|[Click Here](#7️⃣-environment--dependency-issues)|
----

### 1️⃣ API Key Issues
```
❌ Error: Invalid API key / 401 Unauthorized
```
#### Cause
- API key missing in .env
- Typo in key
- Variable name mis-match. 
- Wrong environment loaded
#### Solution
- Verify `.env` file exists at project root
- Ensure correct variable name:
    ```
    SHODAN_API_KEY=xxxxxxxx
    ```
- Restart terminal after editing .env
- Print and verify
    ```python
    from dotenv import load_dotenv, 
    import os
    find_dotenv
    load_dotenv(find_dotenv)
    secret = os.getenv("SHODAN_API_KEY")
    if secret is not NULL:
        print(f"API key is ready")
    else:
        print(f"Couldn't find the API key")
    ```
    _____
```
❌ Error: 403 Forbidden / Access denied
```
#### Cause
- API key permissions insufficient
- Rate limit exceeded
- API plan limitations
#### Solution
- Check API plan on provider dashboard
- Reduce request frequency
- Cache results locally
- Use test data for development
_______
### 2️⃣ Network & Connectivity Issues
```
❌ Error: ConnectionError, Timeout
```
#### Cause
- Internet connectivity issues
- API provider temporarily unavailable
- Firewall / proxy blocking requests
#### Solution
- Check internet connection. 
- Retry after some time. 
- Test endpoint using browser or curl. 
- Use VPN only if permitted.
______
### 3️⃣ Data Not Found / Empty Results
```
❌ No results from Shodan/Vulners/VirusTotal
```
#### Cause
- Query too specific
- IP not indexed
- CVE not present in source
#### Solution
- Test with known sample inputs
- Verify input values (public IPs only for Shodan)
- Try broader queries
- Validate input JSON structure from Layer-1
______
### 4️⃣ JSON Parsing Errors
```
❌ Error: KeyError, TypeError, JSONDecodeError
```
#### Cause
- Missing expected fields.
- API response format change.
- Empty or malformed JSON.
#### Solution
- Always use `.get()` instead of direct indexing.
- Add validation checks:
    ```python
    if 'matches' not in data:
        handle_empty_responses()
    ```
- Log raw response for debugging. 
________
### 5️⃣ Rate Limiting Issues
```
❌ Error: 429 Too Many Requests
```
#### Cause
- API request limit exceeded
#### Solution
- Add request throttling
- Introduce `sleep()` between calls
- Cache results
- Batch queries where supported
_________
### 6️⃣ Map / Visualization Issues (Shodan Map)
```
❌ Map shows fewer points than expected
```
#### Cause
- Multiple IPs share same geolocation
- Clustering enabled by map library
#### Solution
- Zoom in to view clustered points
- Enable marker clustering intentionally
- This is expected behavior, not a bug. 
    ______
```
❌ Map tiles not loading
```
#### Cause
- Tile provider requires authentication
- Internet access blocked
#### Solution
- Use free tile providers only:
    - OpenStreetMap
    - CartoDB
- Avoid paid satellite tiles unless keys are configured
______
### 7️⃣ Environment & Dependency Issues
```
❌ Module not found (ModuleNotFoundError)
```
#### Cause
- Virtual environment not activated
- Dependencies not installed
#### Solution
```bash
source venv/bin/activate # linux
venv\Scripts\activate # windows
pip install -r requirements.txt
```

______
[Click Here to go back to the README file](README.md)