import json
from datetime import datetime

from core.input_parser import InputParser
from core.validator import Validator
from core.risk_summary_builder import build_risk_input

from tools.shodan_tool import ShodanTool
from tools.virustotal_tool import VirusTotalTool
from tools.nvd_tool import NVDTool
from tools.vulners_tool import VulnersTool
from tools.cisa_kev_tool import CISAKEVTool


class ThreatIntelPipeline:
    def __init__(self):
        self.parser = InputParser()
        self.validator = Validator()

        # Safe initialization
        try:
            self.shodan = ShodanTool()
        except Exception as e:
            print(f"⚠️  Failed to initialize Shodan: {e}")
            self.shodan = None

        try:
            self.virustotal = VirusTotalTool()
        except Exception as e:
            print(f"⚠️  Failed to initialize VirusTotal: {e}")
            self.virustotal = None

        try:
            self.nvd = NVDTool()
        except Exception as e:
            print(f"⚠️  Failed to initialize NVD: {e}")
            self.nvd = None

        try:
            self.vulners = VulnersTool()
        except Exception as e:
            print(f"⚠️  Failed to initialize Vulners: {e}")
            self.vulners = None

        try:
            self.cisa = CISAKEVTool()
        except Exception as e:
            print(f"⚠️  Failed to initialize CISA KEV: {e}")
            self.cisa = None

    # ==================================================
    def run(self, input_file: str) -> dict:
        print("\n" + "="*60)
        print("🚀 Starting Threat Intelligence Pipeline")
        print("="*60)
        
        try:
            parsed = self.parser.parse(input_file)
            print("✅ Input parsed successfully")
        except Exception as e:
            print(f"❌ Failed to parse input: {e}")
            return {"status": "failed", "errors": [f"Parse error: {str(e)}"]}

        validation = self.validator.validate(parsed)

        if not validation["is_valid"]:
            print(f"❌ Validation failed: {validation['errors']}")
            return {"status": "failed", "errors": validation["errors"]}

        print("✅ Input validation passed")

        asset = parsed["asset"]
        vulns = parsed["vulnerabilities"]
        cves = [v["cve"] for v in vulns if v.get("cve")]
        
        print(f"📊 Processing {len(vulns)} vulnerabilities, {len(cves)} CVEs")
        print(f"🎯 Target asset: {asset.get('ip')} ({asset.get('hostname', 'no hostname')})")

        # ---------------- INTELLIGENCE ----------------
        print("\n🔍 Gathering intelligence data...")
        intel = {
            "shodan": self._safe_query(self.shodan, asset.get("ip")),
            "virustotal": self._safe_query(self.virustotal, asset.get("ip")),
            "nvd": self._safe_query(self.nvd, cves),
            "vulners": self._safe_query(self.vulners, cves),
            "cisa_kev": self._safe_query(self.cisa, cves)
        }

        # ---------------- LEVEL 2 ----------------
        print("\n📄 Generating Level 2 output...")
        level2 = {
            "asset": asset,
            "vulnerabilities": vulns,
            "intelligence": intel,
            "generated_at": datetime.utcnow().isoformat()
        }

        with open("output/level2.json", "w") as f:
            json.dump(level2, f, indent=2)
        print("✅ Saved level2.json")

        # ---------------- LAYER 3 ----------------
        print("\n📊 Building risk summary...")
        risk_input = build_risk_input(level2)
        with open("output/risk_input.json", "w") as f:
            json.dump(risk_input, f, indent=2)
        print("✅ Saved risk_input.json")

        # ---------------- DASHBOARD ----------------
        print("\n📈 Generating dashboard summary...")
        dashboard = self._generate_dashboard_summary(asset, vulns, intel)
        with open("output/dashboard_summary.json", "w") as f:
            json.dump(dashboard, f, indent=2)
        print("✅ Saved dashboard_summary.json")

        # ---------------- SHODAN MAP ----------------
        print("\n🗺️  Generating Shodan map...")
        shodan_map = self._generate_shodan_map()
        with open("output/shodan_map_points.json", "w") as f:
            json.dump(shodan_map, f, indent=2, default=str)  # default=str handles non-serializable objects
        print("✅ Saved shodan_map_points.json")
        
        # Print map stats
        total_points = shodan_map.get("total_points", 0)
        error = shodan_map.get("error")
        if error:
            print(f"⚠️  Map generation had issues: {error}")
        print(f"📍 Generated {total_points} map points")

        print("\n" + "="*60)
        print("✅ Pipeline completed successfully!")
        print("="*60)
        
        return {"status": "success"}

    # ==================================================
    def _safe_query(self, tool, target):
        if tool is None:
            return {"skipped": True, "reason": "Tool not initialized"}
        if not target:
            return {"skipped": True, "reason": "No target provided"}
        
        try:
            print(f"  🔧 Querying {tool.__class__.__name__}...")
            result = tool.query(target)
            if "error" in result:
                print(f"  ⚠️  {tool.__class__.__name__} error: {result.get('error')}")
            elif "skipped" in result and result.get("skipped"):
                print(f"  ⚠️  {tool.__class__.__name__} skipped: {result.get('reason', 'Unknown')}")
            else:
                print(f"  ✅ {tool.__class__.__name__} query successful")
            return result
        except Exception as e:
            error_msg = f"{tool.__class__.__name__} exception: {str(e)}"
            print(f"  ❌ {error_msg}")
            return {"error": error_msg}

    # ==================================================
    # SHODAN MAP (SEARCH-BASED) - IMPROVED VERSION
    # ==================================================
        # ==================================================
    # SHODAN MAP (SEARCH-BASED) - IMPROVED WITH COORDINATE VALIDATION
    # ==================================================
    def _generate_shodan_map(self):
        # Use a broader query that's more likely to return results
        query = "port:22"
        print(f"  🔍 Query: '{query}'")

        if self.shodan is None:
            print("  ❌ Shodan tool not available")
            return {
                "generated_at": datetime.utcnow().isoformat(),
                "query": query,
                "total_points": 0,
                "points": [],
                "error": "Shodan tool not initialized",
                "debug": "Check if SHODAN_API_KEY is set in .env file"
            }

        print("  📡 Querying Shodan API...")
        result = self.shodan.search(query, limit=50)  # Start with smaller limit
        
        if not isinstance(result, dict):
            print(f"  ❌ Invalid response type: {type(result)}")
            return {
                "generated_at": datetime.utcnow().isoformat(),
                "query": query,
                "total_points": 0,
                "points": [],
                "error": f"Invalid response type: {type(result)}",
                "raw_response": str(result)[:200]
            }
        
        # Check for errors
        if "error" in result:
            print(f"  ❌ Shodan API error: {result.get('error')}")
            return {
                "generated_at": datetime.utcnow().isoformat(),
                "query": query,
                "total_points": 0,
                "points": [],
                "error": result.get("error"),
                "details": result.get("details", ""),
                "status_code": result.get("status_code")
            }
        
        if "skipped" in result and result.get("skipped"):
            print(f"  ⚠️  Shodan search skipped: {result.get('reason', 'Unknown')}")
            return {
                "generated_at": datetime.utcnow().isoformat(),
                "query": query,
                "total_points": 0,
                "points": [],
                "error": result.get("reason", "Search skipped")
            }

        matches = result.get("matches", [])
        total_results = result.get("total", 0)
        
        print(f"  📊 Shodan returned {len(matches)} matches (total available: {total_results})")

        points = []
        valid_coords_count = 0
        zero_coords_count = 0
        invalid_coords_count = 0
        
        for i, item in enumerate(matches):
            if not isinstance(item, dict):
                continue
                
            # Get location data
            loc = item.get("location", {})
            lat = loc.get("latitude")
            lon = loc.get("longitude")
            
            # Skip if missing coordinates
            if lat is None or lon is None:
                if i < 3:  # Only debug first few
                    print(f"  ⚠️  Match {i} skipped: Missing coordinates (lat={lat}, lon={lon})")
                invalid_coords_count += 1
                continue
            
            # Convert to float and validate
            try:
                lat_float = float(lat)
                lon_float = float(lon)
                
                # Check for zero coordinates (0,0 is in the ocean near Africa)
                if lat_float == 0.0 and lon_float == 0.0:
                    if i < 3:
                        print(f"  ⚠️  Match {i} has zero coordinates (0,0) - skipping")
                    zero_coords_count += 1
                    continue
                
                # Check for valid coordinate ranges
                if lat_float < -90 or lat_float > 90 or lon_float < -180 or lon_float > 180:
                    if i < 3:
                        print(f"  ⚠️  Match {i} has invalid coordinates ({lat_float}, {lon_float}) - skipping")
                    invalid_coords_count += 1
                    continue
                
                # Check for obviously wrong coordinates (e.g., in the ocean near Africa)
                if lat_float == 0.0 or lon_float == 0.0:
                    if i < 3:
                        print(f"  ⚠️  Match {i} has suspicious zero coordinate ({lat_float}, {lon_float})")
                
                valid_coords_count += 1
                
                # Ensure all values are JSON-serializable
                point = {
                    "id": i,
                    "ip": str(item.get("ip_str", "")),
                    "lat": lat_float,
                    "lon": lon_float,
                    "country": str(loc.get("country_name", "Unknown")),
                    "city": str(loc.get("city", "Unknown")),
                    "org": str(item.get("org", "Unknown")),
                    "ports": [int(p) for p in item.get("ports", []) if isinstance(p, (int, float, str)) and str(p).isdigit()][:5],
                    "product": str(item.get("product", "Unknown")),
                    "timestamp": item.get("timestamp", "")
                }
                
                # Add banner if available (truncated)
                if "data" in item:
                    banner = str(item["data"])[:100]
                    point["banner_preview"] = banner
                
                points.append(point)
                
                # Debug first few points
                if i < 3:
                    print(f"  ✅ Match {i} added: {point['ip']} at ({point['lat']}, {point['lon']})")
                
            except (ValueError, TypeError) as e:
                print(f"  ⚠️  Error processing match {i}: {e}")
                invalid_coords_count += 1
                continue

        print(f"  📊 Coordinate stats: {valid_coords_count} valid, {zero_coords_count} zero-coords, {invalid_coords_count} invalid")
        print(f"  ✅ Successfully processed {len(points)} points with valid coordinates")
        
        # Create final result
        map_data = {
            "generated_at": datetime.utcnow().isoformat(),
            "query": query,
            "total_points": len(points),
            "total_available": total_results,
            "limit_used": 50,
            "coordinate_stats": {
                "valid": valid_coords_count,
                "zero_coordinates": zero_coords_count,
                "invalid": invalid_coords_count
            },
            "points": points
        }
        
        # Add debug info if no points were generated
        if len(points) == 0 and len(matches) > 0:
            print(f"  ⚠️  Warning: Processed {len(matches)} matches but got 0 points")
            print(f"  🔍 Debug - First match structure keys: {list(matches[0].keys()) if matches else 'No matches'}")
            print(f"  🔍 Debug - First match location: {matches[0].get('location', {}) if matches else {}}")
            map_data["debug_info"] = {
                "matches_received": len(matches),
                "first_match_keys": list(matches[0].keys()) if matches else [],
                "sample_location": matches[0].get("location", {}) if matches else {},
                "all_locations_sample": [
                    m.get("location", {}) for m in matches[:3]
                ]
            }
        
        return map_data




    # ==================================================
    def _generate_dashboard_summary(self, asset, vulns, intel):
        cvss_scores = []
        for v in vulns:
            cvss = v.get("cvss")
            if cvss is not None:
                try:
                    cvss_scores.append(float(cvss))
                except (ValueError, TypeError):
                    pass
        
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0
        max_cvss = max(cvss_scores) if cvss_scores else 0

        severity_dist = {}
        for v in vulns:
            sev = v.get("severity", "UNKNOWN")
            severity_dist[sev] = severity_dist.get(sev, 0) + 1

        kev_count = 0
        cisa_kev = intel.get("cisa_kev", {})
        if isinstance(cisa_kev, dict):
            kev_count = len([k for k in cisa_kev.keys() if k and k != "error" and k != "skipped"])

        return {
            "dashboard_version": "1.0",
            "generated_at": datetime.utcnow().isoformat(),
            "asset_summary": asset,
            "vulnerability_metrics": {
                "total_vulnerabilities": len(vulns),
                "average_cvss": avg_cvss,
                "highest_cvss": max_cvss,
                "severity_distribution": severity_dist,
                "kev_exploited_count": kev_count
            },
            "risk": {
                "risk_level": self._calculate_risk(avg_cvss, max_cvss, kev_count)
            }
        }

    # ==================================================
    def _calculate_risk(self, avg, max_score, kev):
        if kev > 0 or max_score >= 9:
            return "CRITICAL"
        if max_score >= 7:
            return "HIGH"
        if avg >= 4:
            return "MEDIUM"
        return "LOW"