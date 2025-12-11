import folium
from folium.plugins import MarkerCluster
import os
import json

def get_details(file_path):
    location_list = []
    with open (file_path, "r", encoding="utf-8") as f:
        content_of_json = json.load(f)
    for item in content_of_json['matches']:
        ip = item.get("ip_str")
        lat = item['location'].get('latitude')
        long = item['location'].get('longitude')
        elem_dict = {"ip": ip, "lat": lat, "long":long}
        location_list.append(elem_dict)
    return location_list
def get_map_file_path(file_body_name):
    pwd = os.path.dirname(os.path.abspath(__file__))
    map_folder_path = os.path.join(pwd, "..", "shodan_maps")
    os.makedirs(map_folder_path, exist_ok=True)
    file_name_with_ext = file_body_name + ".html"
    file_path = os.path.join(map_folder_path, file_name_with_ext)
    return file_path

def generate_map(file_path, file_name):
    data = get_details(file_path)
    world_map = folium.Map(location=[20, 0], zoom_start=2, tiles='openstreetmap')
    cluster = MarkerCluster().add_to(world_map)
    folium.TileLayer('CartoDB positron', attr="positron").add_to(world_map)
    folium.TileLayer(
    tiles="https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
    attr="Tiles © Esri — Source: Esri, Maxar, Earthstar Geographics, GIS User Community",
    name="Esri Satellite"
    ).add_to(world_map)
    folium.TileLayer('https://cartodb-basemaps-a.global.ssl.fastly.net/light_all/{z}/{x}/{y}.png', attr="tty").add_to(world_map)
    folium.TileLayer('CartoDb dark_matter', attr="dark").add_to(world_map)
    folium.LayerControl().add_to(world_map)
    for device in data:
        ip = device['ip']
        lat = device['lat']
        long = device['long']
        if lat is None or long is None:
            continue
        folium.Marker(location=[lat, long], popup=f"IP: {ip}").add_to(cluster)
    save_destination = get_map_file_path(file_name)
    world_map.save(save_destination)
    print(f"Threat Intelligence Update: Shodan result map saved...")
    return True