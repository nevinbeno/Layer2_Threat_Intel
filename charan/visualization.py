import requests
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import os
from dotenv import load_dotenv
from collections import defaultdict
import textwrap
import folium  # For interactive maps
from folium import plugins
import ipaddress
import socket
import networkx as nx
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64
import warnings
warnings.filterwarnings('ignore')

# Assuming this exists in your project structure
# from threat_intelligence_engine import ThreatIntelligenceEngine 

# Load API keys from environment
load_dotenv()

class ThreatIntelligenceVisualizer:
    def __init__(self):
        # API Keys
        self.shodan_api_key = os.getenv('SHODAN_API_KEY', 'demo_key')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', 'demo_key')
        self.ipinfo_api_key = os.getenv('IPINFO_API_KEY', 'demo_key')
        
        self.demo_mode = any(key == 'demo_key' for key in 
                            [self.shodan_api_key, self.virustotal_api_key, self.ipinfo_api_key])
        
        # Visualization storage
        self.visualizations = {}
        self.geo_data = []
        
    def generate_all_visualizations(self, threat_data: Dict) -> Dict:
        """Generate all visualization types"""
        
        print("\n🎨 Generating Visualizations...")
        print("="*50)
        
        # 1. GEOGRAPHIC MAPS
        print("📍 Generating Geographic Maps...")
        self.visualizations['geographic'] = self.generate_geographic_maps(threat_data)
        
        # 2. NETWORK GRAPHS
        print("🔗 Generating Network Graphs...")
        self.visualizations['network'] = self.generate_network_graphs(threat_data)
        
        # 3. TIMELINE VISUALIZATIONS
        print("📅 Generating Timeline Visualizations...")
        self.visualizations['timeline'] = self.generate_timeline_visualizations(threat_data)
        
        # 4. HEATMAPS
        print("🔥 Generating Heatmaps...")
        self.visualizations['heatmaps'] = self.generate_heatmaps(threat_data)
        
        # 5. 3D VISUALIZATIONS
        print("🌐 Generating 3D Visualizations...")
        self.visualizations['3d'] = self.generate_3d_visualizations(threat_data)
        
        # 6. DASHBOARD COMPONENTS
        print("📊 Generating Dashboard Components...")
        self.visualizations['dashboard'] = self.generate_dashboard_components(threat_data)
        
        # 7. EXPORT ALL VISUALIZATIONS
        print("💾 Exporting Visualizations...")
        export_paths = self.export_visualizations()
        
        return {
            'visualizations': self.visualizations,
            'export_paths': export_paths,
            'geo_data': self.geo_data
        }
    
    def generate_geographic_maps(self, threat_data: Dict) -> Dict:
        """Generate geographic maps showing threat locations"""
        
        maps = {}
        
        # Get IP locations from Shodan data
        shodan_results = threat_data.get('shodan_results', {}).get('data', {})
        scan_data = threat_data.get('scan_data', {})
        
        # Create a base map
        base_map = folium.Map(location=[20, 0], zoom_start=2)
        
        # Add IP locations
        locations = []
        
        # 1. Main target IP
        target_ip = scan_data.get('ip', '8.8.8.8')
        target_location = self.get_ip_location(target_ip)
        if target_location:
            folium.Marker(
                location=[target_location['lat'], target_location['lon']],
                popup=f"<b>Target:</b> {target_ip}<br>"
                      f"<b>Organization:</b> {target_location.get('org', 'Unknown')}<br>"
                      f"<b>Country:</b> {target_location.get('country', 'Unknown')}",
                icon=folium.Icon(color='red', icon='bullseye', prefix='fa')
            ).add_to(base_map)
            locations.append({
                'ip': target_ip,
                'lat': target_location['lat'],
                'lon': target_location['lon'],
                'type': 'target',
                'threat_level': 'high'
            })
        
        # 2. Related IPs from Shodan
        if shodan_results and 'host_info' in shodan_results:
            org = shodan_results['host_info'].get('org', 'Unknown')
            city = shodan_results['host_info'].get('city', 'Unknown')
            country = shodan_results['host_info'].get('country', 'Unknown')
            
            # Get coordinates for organization location
            org_coords = self.geocode_location(f"{city}, {country}")
            if org_coords:
                folium.Marker(
                    location=[org_coords[0], org_coords[1]],
                    popup=f"<b>Organization:</b> {org}<br>"
                          f"<b>Location:</b> {city}, {country}<br>"
                          f"<b>Services Found:</b> {len(shodan_results.get('services', []))}",
                    icon=folium.Icon(color='blue', icon='building', prefix='fa')
                ).add_to(base_map)
        
        # 3. Threat actor locations (simulated - real data would come from threat intel)
        threat_actors = [
            {'name': 'APT Group', 'country': 'Russia', 'city': 'Moscow', 'type': 'nation_state'},
            {'name': 'Cybercrime Group', 'country': 'China', 'city': 'Beijing', 'type': 'criminal'},
            {'name': 'Hacktivist', 'country': 'USA', 'city': 'San Francisco', 'type': 'activist'}
        ]
        
        for actor in threat_actors:
            coords = self.geocode_location(f"{actor['city']}, {actor['country']}")
            if coords:
                folium.Marker(
                    location=[coords[0], coords[1]],
                    popup=f"<b>Threat Actor:</b> {actor['name']}<br>"
                          f"<b>Type:</b> {actor['type']}<br>"
                          f"<b>Location:</b> {actor['city']}, {actor['country']}",
                    icon=folium.Icon(
                        color='orange' if actor['type'] == 'nation_state' else 'purple',
                        icon='user-secret' if actor['type'] == 'nation_state' else 'user',
                        prefix='fa'
                    )
                ).add_to(base_map)
        
        # 4. Add heatmap layer
        if len(locations) > 0:
            heat_data = [[loc['lat'], loc['lon'], 1] for loc in locations]
            plugins.HeatMap(heat_data, radius=15).add_to(base_map)
        
        # 5. Add threat lines (simulated attack paths)
        if len(locations) > 1:
            for i in range(len(locations)-1):
                folium.PolyLine(
                    locations=[
                        [locations[i]['lat'], locations[i]['lon']],
                        [locations[i+1]['lat'], locations[i+1]['lon']]
                    ],
                    color='red',
                    weight=2,
                    opacity=0.5,
                    popup='Potential Attack Path'
                ).add_to(base_map)
        
        # Save the map
        map_path = "threat_geographic_map.html"
        base_map.save(map_path)
        
        # Create Plotly map for embedded display
        fig = go.Figure()
        
        # Add scatter points
        if locations:
            lats = [loc['lat'] for loc in locations]
            lons = [loc['lon'] for loc in locations]
            types = [loc['type'] for loc in locations]
            
            fig.add_trace(go.Scattergeo(
                lon=lons,
                lat=lats,
                text=[f"IP: {loc['ip']}" for loc in locations],
                mode='markers',
                marker=dict(
                    size=10,
                    color=['red' if t == 'target' else 'blue' for t in types],
                    symbol='circle'
                ),
                name='IP Locations'
            ))
        
        # Update layout
        fig.update_layout(
            title='Threat Intelligence Geographic Map',
            geo=dict(
                projection_type='natural earth',
                showland=True,
                landcolor='rgb(243, 243, 243)',
                countrycolor='rgb(204, 204, 204)'
            )
        )
        
        maps['interactive_map'] = map_path
        maps['plotly_map'] = fig.to_dict()
        maps['locations'] = locations
        
        return maps
    
    def generate_network_graphs(self, threat_data: Dict) -> Dict:
        """Generate network relationship graphs"""
        
        graphs = {}
        
        # Create a directed graph
        G = nx.DiGraph()
        
        # Extract data for graph
        scan_data = threat_data.get('scan_data', {})
        shodan_data = threat_data.get('shodan_results', {}).get('data', {})
        nvd_data = threat_data.get('nvd_results', {}).get('data', {})
        vt_data = threat_data.get('virustotal_results', {}).get('data', {})
        
        # Add nodes with attributes
        # 1. Target node
        target_ip = scan_data.get('ip', '8.8.8.8')
        G.add_node(target_ip, 
                  type='target', 
                  size=20,
                  color='red',
                  label=f"Target: {target_ip}")
        
        # 2. Service nodes
        for port_info in scan_data.get('ports', []):
            service_id = f"service_{port_info.get('port')}"
            G.add_node(service_id,
                      type='service',
                      size=15,
                      color='blue',
                      label=f"{port_info.get('service', 'Unknown')}:{port_info.get('port')}")
            G.add_edge(service_id, target_ip, 
                      label='runs_on',
                      weight=2)
        
        # 3. Vulnerability nodes
        for vuln in scan_data.get('vulnerabilities', []):
            cve_id = vuln.get('cve')
            if cve_id:
                G.add_node(cve_id,
                          type='vulnerability',
                          size=18,
                          color='orange',
                          label=f"{cve_id}")
                
                # Connect vulnerabilities to services
                for port_info in scan_data.get('ports', []):
                    service_id = f"service_{port_info.get('port')}"
                    G.add_edge(cve_id, service_id,
                              label='affects',
                              weight=3)
        
        # 4. Threat actor nodes
        threat_actors = [
            ('APT29', 'nation_state', 'red'),
            ('Lazarus Group', 'criminal', 'purple'),
            ('FIN7', 'criminal', 'orange')
        ]
        
        for actor, actor_type, color in threat_actors:
            G.add_node(actor,
                      type='threat_actor',
                      size=25,
                      color=color,
                      label=f"{actor}")
            # Connect threat actors to vulnerabilities they exploit
            for vuln in scan_data.get('vulnerabilities', []):
                cve_id = vuln.get('cve')
                if cve_id:
                    G.add_edge(actor, cve_id,
                              label='exploits',
                              weight=4)
        
        # 5. C2 server nodes
        c2_servers = ['185.220.101.101', '45.133.1.150', '91.92.109.244']
        for c2_ip in c2_servers[:2]:  # Limit to 2 for clarity
            G.add_node(c2_ip,
                      type='c2_server',
                      size=22,
                      color='black',
                      label=f"C2: {c2_ip}")
            # Connect C2 to threat actors
            G.add_edge(c2_ip, 'APT29',
                      label='controlled_by',
                      weight=2)
        
        # Generate graph visualization
        plt.figure(figsize=(16, 12))
        
        # Use spring layout
        pos = nx.spring_layout(G, k=2, iterations=50)
        
        # Draw nodes by type
        node_colors = []
        node_sizes = []
        for node in G.nodes():
            node_colors.append(G.nodes[node].get('color', 'gray'))
            node_sizes.append(G.nodes[node].get('size', 10))
        
        # Draw the graph
        nx.draw_networkx_nodes(G, pos, 
                              node_color=node_colors, 
                              node_size=node_sizes,
                              alpha=0.8)
        
        # Draw edges with different styles
        edge_weights = [G[u][v].get('weight', 1) for u, v in G.edges()]
        nx.draw_networkx_edges(G, pos, 
                              width=[w/2 for w in edge_weights],
                              alpha=0.5,
                              edge_color='gray')
        
        # Draw labels
        labels = {node: G.nodes[node].get('label', node) for node in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels, font_size=8)
        
        # Draw edge labels
        edge_labels = {(u, v): G[u][v].get('label', '') for u, v in G.edges()}
        nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=7)
        
        plt.title('Threat Intelligence Network Graph', fontsize=16, pad=20)
        plt.axis('off')
        
        # Save the graph
        graph_path = "threat_network_graph.png"
        plt.savefig(graph_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        # Create interactive Plotly version
        edge_trace = go.Scatter(
            x=[], y=[],
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace['x'] += tuple([x0, x1, None])
            edge_trace['y'] += tuple([y0, y1, None])
        
        node_trace = go.Scatter(
            x=[], y=[],
            mode='markers+text',
            hoverinfo='text',
            marker=dict(
                showscale=True,
                colorscale='Viridis',
                size=[],
                color=[],
                line_width=2))
        
        for node in G.nodes():
            x, y = pos[node]
            node_trace['x'] += tuple([x])
            node_trace['y'] += tuple([y])
            node_trace['marker']['size'] += tuple([G.nodes[node].get('size', 10)])
            node_trace['marker']['color'] += tuple([1])  # Placeholder
        
        # Create Plotly figure
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title='Interactive Threat Network',
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20, l=5, r=5, t=40),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                       )
        
        graphs['static_graph'] = graph_path
        graphs['interactive_graph'] = fig.to_dict()
        graphs['graph_data'] = {
            'nodes': list(G.nodes(data=True)),
            'edges': list(G.edges(data=True)),
            'node_count': G.number_of_nodes(),
            'edge_count': G.number_of_edges()
        }
        
        return graphs
    
    def generate_timeline_visualizations(self, threat_data: Dict) -> Dict:
        """Generate timeline visualizations of threats"""
        
        timelines = {}
        
        # Extract timeline data
        nvd_data = threat_data.get('nvd_results', {}).get('data', {})
        kev_data = threat_data.get('cisa_kev_results', {}).get('data', {})
        
        # Prepare data for timeline
        timeline_events = []
        
        # 1. CVE publication dates
        for cve_id, details in nvd_data.items():
            if isinstance(details, dict) and 'published_date' in details:
                try:
                    pub_date = details['published_date'].split('T')[0]
                    cvss_score = details.get('cvss_metrics', {}).get('baseScore', 0)
                    
                    timeline_events.append({
                        'date': pub_date,
                        'event': f'CVE Published: {cve_id}',
                        'type': 'vulnerability',
                        'severity': 'CRITICAL' if cvss_score >= 9.0 else 
                                   'HIGH' if cvss_score >= 7.0 else 
                                   'MEDIUM' if cvss_score >= 4.0 else 'LOW',
                        'details': f"CVSS Score: {cvss_score}",
                        'color': '#FF6B6B' if cvss_score >= 9.0 else 
                                '#FFA726' if cvss_score >= 7.0 else 
                                '#42A5F5' if cvss_score >= 4.0 else '#66BB6A'
                    })
                except:
                    continue
        
        # 2. KEV addition dates
        for cve_id, kev_info in kev_data.items():
            if 'date_added' in kev_info:
                timeline_events.append({
                    'date': kev_info['date_added'],
                    'event': f'Added to CISA KEV: {cve_id}',
                    'type': 'exploitation',
                    'severity': 'CRITICAL',
                    'details': f"Known exploited vulnerability",
                    'color': '#DC3545'
                })
        
        # 3. Simulated attack events (real system would have actual data)
        attack_events = [
            {'date': '2024-01-10', 'event': 'Initial compromise detected', 'type': 'attack'},
            {'date': '2024-01-12', 'event': 'Lateral movement observed', 'type': 'attack'},
            {'date': '2024-01-15', 'event': 'Data exfiltration attempt', 'type': 'attack'},
        ]
        
        for event in attack_events:
            timeline_events.append({
                'date': event['date'],
                'event': event['event'],
                'type': 'attack',
                'severity': 'HIGH',
                'details': 'Suspicious activity detected',
                'color': '#6F42C1'
            })
        
        # Sort by date
        timeline_events.sort(key=lambda x: x['date'])
        
        # Create Plotly timeline
        if timeline_events:
            df = pd.DataFrame(timeline_events)
            
            # Create Gantt chart style timeline
            fig = px.timeline(df, 
                            x_start='date', 
                            x_end='date',  # Same date for point events
                            y='event',
                            color='severity',
                            color_discrete_map={
                                'CRITICAL': '#DC3545',
                                'HIGH': '#FD7E14',
                                'MEDIUM': '#FFC107',
                                'LOW': '#28A745'
                            },
                            hover_data=['details', 'type'],
                            title='Threat Intelligence Timeline')
            
            fig.update_yaxes(autorange="reversed")
            fig.update_layout(
                height=400 + len(timeline_events) * 20,
                showlegend=True,
                xaxis_title="Date",
                yaxis_title="Event"
            )
            
            timelines['plotly_timeline'] = fig.to_dict()
            
            # Create vertical timeline
            fig2 = go.Figure()
            
            for i, event in enumerate(timeline_events):
                fig2.add_trace(go.Scatter(
                    x=[event['date'], event['date']],
                    y=[i, i],
                    mode='markers+text',
                    marker=dict(size=15, color=event['color']),
                    text=[event['event'], ''],
                    textposition="middle right",
                    name=event['type']
                ))
            
            fig2.update_layout(
                title='Threat Event Timeline',
                xaxis_title="Date",
                yaxis=dict(showticklabels=False, showgrid=False),
                showlegend=True
            )
            
            timelines['vertical_timeline'] = fig2.to_dict()
            
            # Create heatmap timeline
            if len(timeline_events) > 5:
                # Group by date and severity
                df['date'] = pd.to_datetime(df['date'])
                df['severity_value'] = df['severity'].map({
                    'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1
                })
                
                heatmap_data = df.groupby(['date', 'severity']).size().unstack(fill_value=0)
                
                fig3 = go.Figure(data=go.Heatmap(
                    z=heatmap_data.values,
                    x=heatmap_data.index.strftime('%Y-%m-%d'),
                    y=heatmap_data.columns,
                    colorscale='RdYlGn_r',
                    showscale=True
                ))
                
                fig3.update_layout(
                    title='Threat Activity Heatmap',
                    xaxis_title="Date",
                    yaxis_title="Severity"
                )
                
                timelines['heatmap_timeline'] = fig3.to_dict()
        
        timelines['events'] = timeline_events
        
        return timelines
    
    def generate_heatmaps(self, threat_data: Dict) -> Dict:
        """Generate various heatmaps for threat analysis"""
        
        heatmaps = {}
        
        # 1. Port exposure heatmap
        scan_data = threat_data.get('scan_data', {})
        ports = [p.get('port') for p in scan_data.get('ports', [])]
        services = [p.get('service', 'unknown') for p in scan_data.get('ports', [])]
        
        if ports:
            # Create port risk matrix
            port_risk = {
                22: 3,    # SSH - High risk
                80: 2,    # HTTP - Medium risk
                443: 2,   # HTTPS - Medium risk
                3389: 4,  # RDP - Very high risk
                445: 4,   # SMB - Very high risk
                21: 3,    # FTP - High risk
                23: 4,    # Telnet - Very high risk
                3306: 3   # MySQL - High risk
            }
            
            risk_values = [port_risk.get(port, 1) for port in ports]
            
            fig = go.Figure(data=go.Heatmap(
                z=[risk_values],
                y=['Port Risk'],
                x=[f"{services[i]}:{ports[i]}" for i in range(len(ports))],
                colorscale='RdYlGn_r',
                showscale=True,
                text=[[f"Port: {p}<br>Risk: {r}" for p, r in zip(ports, risk_values)]],
                texttemplate="%{text}",
                textfont={"size": 10}
            ))
            
            fig.update_layout(
                title='Port Exposure Risk Heatmap',
                height=200,
                xaxis_title="Ports",
                yaxis_title=""
            )
            
            heatmaps['port_heatmap'] = fig.to_dict()
        
        # 2. CVE severity heatmap
        nvd_data = threat_data.get('nvd_results', {}).get('data', {})
        
        if nvd_data:
            cves = list(nvd_data.keys())
            severity_scores = []
            severities = []
            
            for cve_id in cves:
                details = nvd_data[cve_id]
                if isinstance(details, dict):
                    score = details.get('cvss_metrics', {}).get('baseScore', 0)
                    severity_scores.append(score)
                    severities.append(details.get('severity', 'UNKNOWN'))
            
            if severity_scores:
                # Create severity matrix
                severity_matrix = []
                for score in severity_scores:
                    if score >= 9.0:
                        severity_matrix.append([4])  # Critical
                    elif score >= 7.0:
                        severity_matrix.append([3])  # High
                    elif score >= 4.0:
                        severity_matrix.append([2])  # Medium
                    else:
                        severity_matrix.append([1])  # Low
                
                fig2 = go.Figure(data=go.Heatmap(
                    z=severity_matrix,
                    y=['CVSS Severity'],
                    x=cves,
                    colorscale=[[0, '#66BB6A'], [0.25, '#66BB6A'],
                               [0.25, '#42A5F5'], [0.5, '#42A5F5'],
                               [0.5, '#FFA726'], [0.75, '#FFA726'],
                               [0.75, '#FF6B6B'], [1.0, '#FF6B6B']],
                    showscale=True,
                    hoverongaps=False,
                    text=[[f"{cve}<br>Score: {score}<br>Severity: {sev}" 
                          for cve, score, sev in zip(cves, severity_scores, severities)]],
                    texttemplate="%{text}",
                    textfont={"size": 8}
                ))
                
                fig2.update_layout(
                    title='CVE Severity Heatmap',
                    height=150,
                    xaxis_title="CVE IDs",
                    yaxis_title=""
                )
                
                heatmaps['cve_heatmap'] = fig2.to_dict()
        
        # 3. Threat correlation heatmap
        # Simulating threat actor correlation matrix
        threat_actors = ['APT29', 'Lazarus', 'FIN7', 'Cobalt', 'TA505']
        correlation_matrix = [
            [1.0, 0.3, 0.1, 0.2, 0.4],
            [0.3, 1.0, 0.2, 0.1, 0.3],
            [0.1, 0.2, 1.0, 0.4, 0.6],
            [0.2, 0.1, 0.4, 1.0, 0.5],
            [0.4, 0.3, 0.6, 0.5, 1.0]
        ]
        
        fig3 = go.Figure(data=go.Heatmap(
            z=correlation_matrix,
            x=threat_actors,
            y=threat_actors,
            colorscale='Viridis',
            showscale=True,
            text=[[f"{threat_actors[i]} - {threat_actors[j]}: {correlation_matrix[i][j]:.2f}" 
                  for j in range(len(threat_actors))] 
                  for i in range(len(threat_actors))],
            texttemplate="%{text}",
            textfont={"size": 8}
        ))
        
        fig3.update_layout(
            title='Threat Actor Correlation Matrix',
            height=400,
            width=500
        )
        
        heatmaps['correlation_heatmap'] = fig3.to_dict()
        
        return heatmaps
    
    def generate_3d_visualizations(self, threat_data: Dict) -> Dict:
        """Generate 3D visualizations of threat data"""
        
        visualizations_3d = {}
        
        # 1. 3D Threat Landscape
        fig = go.Figure()
        
        # Simulated threat data points
        threats = [
            {'x': 10, 'y': 5, 'z': 8, 'severity': 9.8, 'type': 'vulnerability', 'name': 'CVE-2021-44228'},
            {'x': 7, 'y': 8, 'z': 6, 'severity': 7.5, 'type': 'vulnerability', 'name': 'CVE-2021-41617'},
            {'x': 3, 'y': 9, 'z': 9, 'severity': 10.0, 'type': 'vulnerability', 'name': 'CVE-2021-34527'},
            {'x': 8, 'y': 2, 'z': 4, 'severity': 5.5, 'type': 'exposure', 'name': 'Open Port 3389'},
            {'x': 5, 'y': 6, 'z': 7, 'severity': 8.2, 'type': 'malware', 'name': 'Emotet Infection'},
        ]
        
        # Add 3D scatter points
        for threat in threats:
            fig.add_trace(go.Scatter3d(
                x=[threat['x']],
                y=[threat['y']],
                z=[threat['z']],
                mode='markers+text',
                marker=dict(
                    size=threat['severity'] * 3,
                    color=threat['severity'],
                    colorscale='RdYlGn_r',
                    showscale=True,
                    opacity=0.8
                ),
                text=[threat['name']],
                textposition="top center",
                name=threat['type']
            ))
        
        fig.update_layout(
            title='3D Threat Landscape Visualization',
            scene=dict(
                xaxis_title='Complexity',
                yaxis_title='Access',
                zaxis_title='Impact',
                camera=dict(
                    eye=dict(x=1.5, y=1.5, z=1.5)
                )
            ),
            height=600
        )
        
        visualizations_3d['threat_landscape_3d'] = fig.to_dict()
        
        # 2. 3D Network Cube
        fig2 = go.Figure()
        
        # Network nodes in 3D space
        nodes_3d = [
            {'x': 0, 'y': 0, 'z': 0, 'name': 'Target', 'type': 'asset', 'size': 20},
            {'x': 2, 'y': 1, 'z': 1, 'name': 'Web Server', 'type': 'service', 'size': 15},
            {'x': 1, 'y': 2, 'z': -1, 'name': 'Database', 'type': 'service', 'size': 15},
            {'x': -2, 'y': -1, 'z': 2, 'name': 'C2 Server', 'type': 'threat', 'size': 18},
            {'x': -1, 'y': 3, 'z': 1, 'name': 'APT29', 'type': 'actor', 'size': 25},
        ]
        
        # Add nodes
        for node in nodes_3d:
            fig2.add_trace(go.Scatter3d(
                x=[node['x']],
                y=[node['y']],
                z=[node['z']],
                mode='markers',
                marker=dict(
                    size=node['size'],
                    color='red' if node['type'] == 'threat' else 
                          'orange' if node['type'] == 'actor' else 
                          'blue' if node['type'] == 'service' else 'green'
                ),
                text=[node['name']],
                name=node['type']
            ))
        
        # Add connections (edges)
        connections = [
            (0, 1), (0, 2), (1, 2),  # Internal network
            (3, 4), (3, 0), (4, 1)   # Attack paths
        ]
        
        for conn in connections:
            node1 = nodes_3d[conn[0]]
            node2 = nodes_3d[conn[1]]
            
            fig2.add_trace(go.Scatter3d(
                x=[node1['x'], node2['x'], None],
                y=[node1['y'], node2['y'], None],
                z=[node1['z'], node2['z'], None],
                mode='lines',
                line=dict(
                    color='red' if conn[0] >= 3 or conn[1] >= 3 else 'blue',
                    width=2
                ),
                showlegend=False
            ))
        
        fig2.update_layout(
            title='3D Network Attack Visualization',
            scene=dict(
                xaxis_title='X',
                yaxis_title='Y',
                zaxis_title='Z'
            ),
            height=600
        )
        
        visualizations_3d['network_3d'] = fig2.to_dict()
        
        return visualizations_3d
    
    def generate_dashboard_components(self, threat_data: Dict) -> Dict:
        """Generate dashboard components for real-time monitoring"""
        
        dashboard = {}
        
        # 1. Threat Level Gauge
        risk_assessment = threat_data.get('risk_assessment', {})
        risk_score = risk_assessment.get('overall_risk_score', 0)
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=risk_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Overall Risk Score", 'font': {'size': 24}},
            delta={'reference': 50, 'increasing': {'color': "red"}},
            gauge={
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                'bar': {'color': "darkblue"},
                'bgcolor': "white",
                'borderwidth': 2,
                'bordercolor': "gray",
                'steps': [
                    {'range': [0, 20], 'color': 'green'},
                    {'range': [20, 40], 'color': 'lightgreen'},
                    {'range': [40, 60], 'color': 'yellow'},
                    {'range': [60, 80], 'color': 'orange'},
                    {'range': [80, 100], 'color': 'red'}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': risk_score
                }
            }
        ))
        
        fig.update_layout(height=300)
        dashboard['risk_gauge'] = fig.to_dict()
        
        # 2. Severity Distribution Sunburst
        nvd_data = threat_data.get('nvd_results', {}).get('data', {})
        severity_counts = defaultdict(int)
        
        for cve_id, details in nvd_data.items():
            if isinstance(details, dict):
                severity = details.get('severity', 'UNKNOWN')
                severity_counts[severity] += 1
        
        labels = []
        parents = []
        values = []
        
        for severity, count in severity_counts.items():
            labels.append(severity)
            parents.append("")
            values.append(count)
        
        fig2 = go.Figure(go.Sunburst(
            labels=labels + ["Total"],
            parents=parents + [""],
            values=values + [sum(values)],
            branchvalues="total"
        ))
        
        fig2.update_layout(
            title="Vulnerability Severity Distribution",
            height=400
        )
        
        dashboard['severity_sunburst'] = fig2.to_dict()
        
        # 3. Real-time Threat Feed (simulated)
        threat_feed = [
            {'time': '10:30:15', 'source': 'CISA', 'event': 'New KEV added: CVE-2023-1234', 'level': 'high'},
            {'time': '10:28:45', 'source': 'VirusTotal', 'event': 'Malicious file detected: trojan.exe', 'level': 'medium'},
            {'time': '10:25:10', 'source': 'Shodan', 'event': 'New service exposed: port 3389', 'level': 'low'},
            {'time': '10:20:30', 'source': 'NVD', 'event': 'Critical CVE published: CVE-2023-5678', 'level': 'critical'},
        ]
        
        # Create scrolling feed visualization
        fig3 = go.Figure()
        
        times = [t['time'] for t in threat_feed]
        events = [t['event'] for t in threat_feed]
        colors = ['red' if t['level'] == 'critical' else 
                 'orange' if t['level'] == 'high' else 
                 'yellow' if t['level'] == 'medium' else 'green' 
                 for t in threat_feed]
        
        fig3.add_trace(go.Scatter(
            x=times,
            y=[1] * len(times),
            mode='markers+text',
            marker=dict(size=20, color=colors),
            text=events,
            textposition="top center"
        ))
        
        fig3.update_layout(
            title='Real-time Threat Feed',
            height=200,
            showlegend=False,
            xaxis=dict(showgrid=False),
            yaxis=dict(showticklabels=False, showgrid=False)
        )
        
        dashboard['threat_feed'] = fig3.to_dict()
        dashboard['threat_feed_data'] = threat_feed
        
        # 4. Attack Surface Metrics
        scan_data = threat_data.get('scan_data', {})
        
        metrics = {
            'Open Ports': len(scan_data.get('ports', [])),
            'Vulnerabilities': len(scan_data.get('vulnerabilities', [])),
            'Services': len(set([p.get('service', '') for p in scan_data.get('ports', [])])),
            'CVEs in KEV': threat_data.get('summary', {}).get('cves_in_kev', 0)
        }
        
        fig4 = go.Figure()
        
        fig4.add_trace(go.Bar(
            x=list(metrics.keys()),
            y=list(metrics.values()),
            marker_color=['#FF6B6B', '#FFA726', '#42A5F5', '#66BB6A'],
            text=list(metrics.values()),
            textposition='auto'
        ))
        
        fig4.update_layout(
            title='Attack Surface Metrics',
            height=300
        )
        
        dashboard['metrics_bar'] = fig4.to_dict()
        
        return dashboard
    
    def get_ip_location(self, ip: str) -> Optional[Dict]:
        """Get geographic location for IP address"""
        try:
            if self.demo_mode:
                # Demo locations for common IPs
                demo_locations = {
                    '8.8.8.8': {'lat': 37.4056, 'lon': -122.0775, 'city': 'Mountain View', 'country': 'US', 'org': 'Google'},
                    '1.1.1.1': {'lat': -33.8688, 'lon': 151.2093, 'city': 'Sydney', 'country': 'AU', 'org': 'Cloudflare'},
                    '192.168.1.1': {'lat': 40.7128, 'lon': -74.0060, 'city': 'New York', 'country': 'US', 'org': 'Private Network'},
                }
                return demo_locations.get(ip, {'lat': 0, 'lon': 0, 'city': 'Unknown', 'country': 'Unknown', 'org': 'Unknown'})
            
            # Real IP geolocation using ipinfo.io
            url = f"https://ipinfo.io/{ip}/json"
            if self.ipinfo_api_key and self.ipinfo_api_key != 'demo_key':
                url += f"?token={self.ipinfo_api_key}"
            
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'loc' in data:
                    lat, lon = data['loc'].split(',')
                    return {
                        'lat': float(lat),
                        'lon': float(lon),
                        'city': data.get('city', 'Unknown'),
                        'country': data.get('country', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'postal': data.get('postal', ''),
                        'region': data.get('region', '')
                    }
        except:
            pass
        
        return None
    
    def geocode_location(self, location_str: str) -> Optional[tuple]:
        """Geocode a location string to coordinates"""
        try:
            if self.demo_mode:
                # Demo coordinates for major cities
                demo_coords = {
                    'Moscow, Russia': (55.7558, 37.6173),
                    'Beijing, China': (39.9042, 116.4074),
                    'San Francisco, USA': (37.7749, -122.4194),
                    'London, UK': (51.5074, -0.1278),
                    'Tokyo, Japan': (35.6762, 139.6503)
                }
                return demo_coords.get(location_str, (0, 0))
            
            geolocator = Nominatim(user_agent="threat_intel_viz")
            location = geolocator.geocode(location_str, timeout=10)
            if location:
                return (location.latitude, location.longitude)
        except:
            pass
        
        return None

    def generate_html_report(self) -> str:
        """
        Generate a basic HTML report.
        (Added placeholder since this method was called but missing in the provided code)
        """
        html_content = f"""
        <html>
            <head><title>Threat Visualization Report</title></head>
            <body>
                <h1>Threat Intelligence Report</h1>
                <p>Generated on: {datetime.now()}</p>
                <p>Visualizations exported successfully.</p>
                <p>See JSON files for details.</p>
            </body>
        </html>
        """
        return html_content
    
    def export_visualizations(self) -> Dict:
        """Export all visualizations to files"""
        
        export_paths = {
            'html': [],
            'images': [],
            'json': [],
            'reports': []
        }
        
        # Export interactive map
        if 'geographic' in self.visualizations:
            map_path = self.visualizations['geographic'].get('interactive_map')
            if map_path and os.path.exists(map_path):
                export_paths['html'].append(map_path)
        
        # Export network graph
        if 'network' in self.visualizations:
            graph_path = self.visualizations['network'].get('static_graph')
            if graph_path and os.path.exists(graph_path):
                export_paths['images'].append(graph_path)
        
        # Export visualizations as JSON with proper serialization
        viz_json_path = "all_visualizations.json"
        
        # Helper function for JSON serialization
        def json_serializer(obj):
            import numpy as np
            
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            elif hasattr(obj, 'tolist'):  # Other array-like objects
                return obj.tolist()
            elif isinstance(obj, (datetime, timedelta)):
                return obj.isoformat()
            elif hasattr(obj, '__dict__'):
                return str(obj)
            else:
                raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        try:
            # Try to serialize with custom handler
            serializable_viz = self._make_visualizations_serializable()
            with open(viz_json_path, 'w') as f:
                json.dump(serializable_viz, f, indent=2, default=json_serializer)
            export_paths['json'].append(viz_json_path)
        except Exception as e:
            print(f"Warning: Could not export JSON visualizations: {e}")
            # Create a simplified version without problematic data
            simplified_viz = {}
            for key, value in self.visualizations.items():
                simplified_viz[key] = {}
                for subkey, subvalue in value.items():
                    if not isinstance(subvalue, (dict, list, str, int, float, bool)):
                        simplified_viz[key][subkey] = str(subvalue)
                    else:
                        simplified_viz[key][subkey] = subvalue
            
            with open(viz_json_path, 'w') as f:
                json.dump(simplified_viz, f, indent=2, default=str)
            export_paths['json'].append(viz_json_path)
        
        # Generate HTML report
        html_report = self.generate_html_report()
        report_path = "threat_visualization_report.html"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_report)
        export_paths['reports'].append(report_path)
        
        # Generate summary PDF (placeholder)
        summary_path = "visualization_summary.txt"
        with open(summary_path, 'w') as f:
            f.write("Threat Intelligence Visualization Summary\n")
            f.write("="*50 + "\n\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Total Visualizations: {len(self.visualizations)}\n")
            f.write("\nAvailable Visualizations:\n")
            for viz_type in self.visualizations:
                f.write(f"  - {viz_type.upper()}\n")
        
        export_paths['reports'].append(summary_path)
        
        return export_paths
    
    def _make_visualizations_serializable(self):
        """Convert visualizations to serializable format"""
        import numpy as np
        
        def make_serializable(obj):
            if isinstance(obj, dict):
                return {k: make_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [make_serializable(item) for item in obj]
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif hasattr(obj, 'tolist'):
                return obj.tolist()
            elif isinstance(obj, (datetime, timedelta)):
                return obj.isoformat()
            else:
                return obj
        
        return make_serializable(self.visualizations)


# Enhanced main function to use visualizer
def main_with_visualizations():
    """Main function with enhanced visualizations"""
    
    print("="*70)
    print("🎨 THREAT INTELLIGENCE VISUALIZATION ENGINE")
    print("="*70)
    
    # First, get threat data (you can integrate with your existing engine)
    # Ensure this module is available or mock it
    try:
        from threat_intelligence_engine import ThreatIntelligenceEngine
        threat_engine = ThreatIntelligenceEngine()
        print("\n🔍 Step 1: Collecting Threat Intelligence...")
        threat_report = threat_engine.generate_threat_report()
    except ImportError:
        print("\n⚠️ ThreatIntelligenceEngine not found. Using Mock Data.")
        threat_report = {'scan_data': {'ip': '8.8.8.8', 'ports': [{'port': 80, 'service': 'http'}]}}

    # Initialize visualizer
    visualizer = ThreatIntelligenceVisualizer()
    
    print("\n🎨 Step 2: Generating Advanced Visualizations...")
    viz_results = visualizer.generate_all_visualizations(threat_report)
    
    print("\n" + "="*70)
    print("✅ VISUALIZATION COMPLETE")
    print("="*70)
    
    # Display summary
    print("\n📊 Generated Visualizations:")
    print("-"*40)
    for viz_type in viz_results['visualizations']:
        print(f"  ✓ {viz_type.upper()}")
    
    print("\n💾 Exported Files:")
    print("-"*40)
    for file_type, paths in viz_results['export_paths'].items():
        for path in paths:
            print(f"  • {path} ({file_type.upper()})")
    
    print("\n📍 Geographic Points:")
    print("-"*40)
    if viz_results.get('geo_data'):
        for point in viz_results['geo_data'][:3]:  # Show first 3
            print(f"  • {point.get('ip', 'Unknown')}: {point.get('city', 'Unknown')}, {point.get('country', 'Unknown')}")
    
    print("\n🎯 Quick Access:")
    print("-"*40)
    print("  1. Open 'threat_visualization_report.html' in browser for interactive dashboard")
    print("  2. View 'threat_geographic_map.html' for interactive threat map")
    print("  3. Check 'threat_network_graph.png' for network visualization")
    
    print("\n" + "="*70)
    print("🚀 Visualization engine ready!")
    print("="*70)

if __name__ == "__main__":
    # Check for required libraries
    required_libs = ['folium', 'plotly', 'networkx', 'pandas']
    missing_libs = []
    
    for lib in required_libs:
        try:
            __import__(lib)
        except ImportError:
            missing_libs.append(lib)
    
    if missing_libs:
        print("❌ Missing required libraries for visualizations:")
        for lib in missing_libs:
            print(f"  - {lib}")
        print("\n📦 Install with: pip install " + " ".join(missing_libs))
    else:
        main_with_visualizations()