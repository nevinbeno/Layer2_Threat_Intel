import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent / "src"))

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from core.pipeline import ThreatIntelPipeline
import webbrowser
import threading
import time

app = FastAPI(
    title="Layer 2 Threat Intelligence API",
    description="Internal API for running the ThreatIntel pipeline",
    version="0.1.0"
)

# Mount static files directory (for JSON outputs)
app.mount("/output", StaticFiles(directory="output"), name="output")

# Set up templates directory
templates_path = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=templates_path)

def open_browser():
    """Open browser to the map after a delay"""
    time.sleep(2)  # Give server time to start
    webbrowser.open("http://127.0.0.1:8000/map")

@app.get("/", response_class=HTMLResponse)
def home():
    """Home page with links to all features"""
    html_content = """
    <html>
        <head>
            <title>Layer 2 Threat Intelligence Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #0f172a; color: white; }
                .container { max-width: 800px; margin: 0 auto; }
                h1 { color: #38bdf8; }
                .card { background: #1e293b; padding: 20px; margin: 20px 0; border-radius: 10px; }
                .btn { display: inline-block; background: #38bdf8; color: white; padding: 10px 20px; 
                       text-decoration: none; border-radius: 5px; margin: 5px; }
                .btn:hover { background: #0ea5e9; }
                .nav { margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Layer 2 Threat Intelligence Dashboard</h1>
                
                <div class="nav">
                    <a href="/map" class="btn">🗺️ Interactive Map</a>
                    <a href="/docs" class="btn">📚 API Documentation</a>
                    <a href="/docs#/default/run_pipeline_layer2_run_pipeline_post" class="btn">🚀 Run Pipeline</a>
                </div>
                
                <div class="card">
                    <h2>Available Endpoints</h2>
                    <ul>
                        <li><a href="/map">Interactive Shodan Map</a> - Visualize global SSH servers</li>
                        <li><a href="/output/level2.json">Level 2 Output</a> - Full intelligence data</li>
                        <li><a href="/output/dashboard_summary.json">Dashboard Summary</a> - Risk metrics</li>
                        <li><a href="/output/shodan_map_points.json">Map Data</a> - Raw map points</li>
                        <li><a href="/output/risk_input.json">Risk Input</a> - Layer 3 risk data</li>
                    </ul>
                </div>
                
                <div class="card">
                    <h2>API Endpoints</h2>
                    <ul>
                        <li><strong>POST /layer2/run-pipeline</strong> - Run the full threat intel pipeline</li>
                        <li><strong>GET /map</strong> - Interactive map visualization</li>
                        <li><strong>GET /output/{filename}</strong> - Access generated JSON files</li>
                    </ul>
                </div>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/map")
def map_page(request: Request):
    """Serve the interactive map page"""
    # Read the map.html file
    map_path = Path(__file__).parent.parent / "output" / "map.html"
    
    # If map.html doesn't exist, create it
    if not map_path.exists():
        create_map_html(map_path)
    
    return FileResponse(map_path)

def create_map_html(filepath: Path):
    """Create a map.html file if it doesn't exist"""
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>Shodan World Exposure Map</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        body { margin: 0; background-color: #0f172a; font-family: Arial, sans-serif; }
        #map { width: 100vw; height: 100vh; }
        .popup { font-size: 13px; line-height: 1.4; }
        .popup b { color: #38bdf8; }
        .control-panel {
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(15, 23, 42, 0.9);
            color: white;
            padding: 15px;
            border-radius: 8px;
            z-index: 1000;
            max-width: 300px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .status-panel {
            position: absolute;
            top: 10px;
            left: 10px;
            background: rgba(15, 23, 42, 0.9);
            color: white;
            padding: 10px 15px;
            border-radius: 8px;
            z-index: 1000;
        }
        .btn {
            background: #38bdf8;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            margin: 5px 0;
            width: 100%;
        }
        .btn:hover { background: #0ea5e9; }
    </style>
</head>
<body>
    <div id="map"></div>
    
    <div class="status-panel" id="status">Loading map...</div>
    
    <div class="control-panel">
        <h3 style="margin-top: 0; color: #38bdf8;">🌍 Shodan Exposure Map</h3>
        <p>Showing SSH servers (port 22) from Shodan scan</p>
        <div id="stats">
            <p><b>Points:</b> <span id="point-count">0</span></p>
            <p><b>Last Updated:</b> <span id="last-updated">Just now</span></p>
        </div>
        <button class="btn" onclick="loadMapData()">🔄 Refresh Data</button>
        <button class="btn" onclick="window.location.href='/'">🏠 Back to Dashboard</button>
        <p style="font-size: 12px; color: #94a3b8; margin-top: 10px;">
            Click on markers for details • Data from Shodan API
        </p>
    </div>

    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        // Initialize map
        const map = L.map("map", { worldCopyJump: true }).setView([20, 0], 2);
        
        // Add dark tiles
        L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
            attribution: "&copy; OpenStreetMap & CARTO",
            subdomains: "abcd",
            maxZoom: 19
        }).addTo(map);
        
        let markers = [];
        
        function loadMapData() {
            const status = document.getElementById('status');
            const pointCount = document.getElementById('point-count');
            const lastUpdated = document.getElementById('last-updated');
            
            status.textContent = "Loading map data...";
            
            // Clear existing markers
            markers.forEach(marker => map.removeLayer(marker));
            markers = [];
            
            // Try different possible paths
            const paths = [
                "/output/shodan_map_points.json",
                "../output/shodan_map_points.json",
                "./shodan_map_points.json"
            ];
            
            let currentPathIndex = 0;
            
            function tryNextPath() {
                if (currentPathIndex >= paths.length) {
                    status.textContent = "❌ Failed to load map data";
                    pointCount.textContent = "0";
                    lastUpdated.textContent = "Failed to load";
                    return;
                }
                
                const path = paths[currentPathIndex];
                console.log(`Trying path: ${path}`);
                
                fetch(path)
                    .then(response => {
                        if (!response.ok) {
                            throw new Error(`HTTP ${response.status}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log(`✅ Loaded ${data.total_points} points`);
                        
                        status.textContent = `✅ Loaded ${data.total_points} points`;
                        pointCount.textContent = data.total_points;
                        lastUpdated.textContent = new Date(data.generated_at).toLocaleTimeString();
                        
                        if (!data.points || data.points.length === 0) {
                            status.textContent = "❌ No data points available";
                            return;
                        }
                        
                        // Add markers
                        data.points.forEach(point => {
                            if (point.lat && point.lon) {
                                const marker = L.marker([point.lat, point.lon], {
                                    title: point.ip
                                }).addTo(map);
                                
                                const popupContent = `
                                    <div class="popup">
                                        <b>IP:</b> ${point.ip}<br/>
                                        <b>Organization:</b> ${point.org || "N/A"}<br/>
                                        <b>Country:</b> ${point.country || "N/A"}<br/>
                                        <b>City:</b> ${point.city || "N/A"}<br/>
                                        <b>Product:</b> ${point.product || "Unknown"}<br/>
                                        <b>Ports:</b> ${point.ports && point.ports.length ? point.ports.join(", ") : "None"}<br/>
                                        ${point.timestamp ? `<b>Scanned:</b> ${new Date(point.timestamp).toLocaleString()}` : ''}
                                    </div>
                                `;
                                
                                marker.bindPopup(popupContent);
                                markers.push(marker);
                            }
                        });
                        
                        // Fit bounds to markers
                        if (markers.length > 0) {
                            const group = new L.featureGroup(markers);
                            map.fitBounds(group.getBounds().pad(0.1));
                        }
                        
                    })
                    .catch(error => {
                        console.warn(`Failed with path ${path}:`, error.message);
                        currentPathIndex++;
                        tryNextPath();
                    });
            }
            
            tryNextPath();
        }
        
        // Load data on page load
        window.addEventListener('DOMContentLoaded', loadMapData);
    </script>
</body>
</html>
    """
    
    # Create the directory if it doesn't exist
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    # Write the HTML file
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

@app.post("/layer2/run-pipeline")
def run_pipeline():
    """Run the full threat intelligence pipeline"""
    pipeline = ThreatIntelPipeline()
    input_file = "input/sample_scan.json"
    
    print("\n" + "="*60)
    print("🚀 Starting Threat Intelligence Pipeline via API")
    print("="*60)
    
    result = pipeline.run(input_file)
    
    response = {
        "status": result["status"],
        "message": "Pipeline completed" if result["status"] == "success" else "Pipeline failed",
        "generated_files": [
            "output/level2.json",
            "output/risk_input.json", 
            "output/dashboard_summary.json",
            "output/shodan_map_points.json"
        ],
        "map_url": "http://127.0.0.1:8000/map",
        "api_docs": "http://127.0.0.1:8000/docs"
    }
    
    # Auto-open the map in browser if pipeline was successful
    if result["status"] == "success":
        print("\n🌐 Auto-opening map in browser...")
        threading.Thread(target=open_browser, daemon=True).start()
    
    return response