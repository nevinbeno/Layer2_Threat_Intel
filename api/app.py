import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))

from fastapi import FastAPI
from core.pipeline import ThreatIntelPipeline

app = FastAPI(
    title="Layer 2 Threat Intelligence API",
    description="Internal API for running the ThreatIntel pipeline",
    version="0.1.0"
)

@app.post("/layer2/run-pipeline")
def run_pipeline():
    """
    Triggers the ThreatIntelPipeline.

    NOTE:
    - Requires sensitive input JSONs present in the runtime environment.
    - Execution is handled by the Layer2 dev team.
    """
    pipeline = ThreatIntelPipeline()
    
    # Placeholder call — execution requires real input files
    # result = pipeline.run(input_file)

    return {
        "status": "API scaffold ready",
        "message": "Pipeline execution requires sensitive inputs"
    }
