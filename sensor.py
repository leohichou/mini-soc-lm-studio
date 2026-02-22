import time
import requests
import uuid
import re
import sys
import os

TOKEN = "SECRET_TOKEN_SOC123"
COLLECTOR_URL = "http://0.0.0.0:6001/events"

def tail_log(file_path, last_position=0):
    """Lit les nouvelles lignes d'un fichier log."""
    try:
        if not os.path.exists(file_path):
            return last_position, []
        
        with open(file_path, 'r') as f:
            f.seek(0, 2)  
            current_size = f.tell()
            
            if current_size < last_position:
                last_position = 0
            
            if current_size > last_position:
                f.seek(last_position)
                lines = f.readlines()
                last_position = current_size
                return last_position, lines
            else:
                return last_position, []
                
    except Exception as e:
        print(f"[SENSOR ERROR] Lecture fichier: {e}")
        return last_position, []

def process_line(line):
    """Traite une ligne de log et envoie les événements."""
    line = line.strip()
    
    ssh_match = re.search(r'Failed password for .* from (\S+)', line)
    if ssh_match:
        ip = ssh_match.group(1)
        data = {
            "event_id": str(uuid.uuid4()),
            "type": "ssh_failed",
            "src_ip": ip,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "details": line
        }
        try:
            response = requests.post(COLLECTOR_URL, json=data, 
                                   headers={"Authorization": f"Bearer {TOKEN}"}, 
                                   timeout=2)
            if response.status_code == 200:
                print(f"[SENSOR] SSH failed → {ip}")
            else:
                print(f"[SENSOR] Erreur HTTP {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[SENSOR] Erreur connexion: {e}")
        return True
    
    scan_match = re.search(r'refused connect from (\S+)', line)
    if scan_match:
        ip = scan_match.group(1)
        data = {
            "event_id": str(uuid.uuid4()),
            "type": "port_scan",
            "src_ip": ip,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "details": line
        }
        try:
            response = requests.post(COLLECTOR_URL, json=data,
                                   headers={"Authorization": f"Bearer {TOKEN}"},
                                   timeout=2)
            if response.status_code == 200:
                print(f"[SENSOR] Port scan → {ip}")
            else:
                print(f"[SENSOR] Erreur HTTP {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[SENSOR] Erreur connexion: {e}")
        return True
    
    return False

def main():
    log_file = '/var/log/auth.log'
    print(f"[SENSOR] Surveillance de {log_file}")
    print("[SENSOR] Appuyez sur Ctrl+C pour arrêter")
    
    last_position = 0
    event_count = 0
    
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            f.seek(0, 2)
            last_position = f.tell()
    
    try:
        while True:
            last_position, new_lines = tail_log(log_file, last_position)
            
            for line in new_lines:
                if process_line(line):
                    event_count += 1
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n[SENSOR] Arrêt. {event_count} événements détectés.")
    except Exception as e:
        print(f"[SENSOR] Erreur: {e}")

if __name__ == "__main__":
    main()
