## Layer 2 API

### Pre requesites: 
- `uvicorn`
- `fastapi`

### Endpoint:
POST /layer2/run-pipeline

### Purpose:
Exposes the ThreatIntelPipeline to upper layers (dashboard).

### Local testing
- Run in bash
    ```bash
    $ uvicorn api.app:app --reload
    ```
- Open: 
    ```
    http://127.0.0.1:8000/docs
    ```
- Click the `endpoint, it is expected to return: 
    ```json
    {
        "status": "API scaffold ready",
        "message": "Pipeline execution requires sensitive inputs"
    }
    ```