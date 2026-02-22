from flask import Flask, request, jsonify
import psycopg2
import requests

app = Flask(__name__)
TOKEN = "SECRET_TOKEN_SOC123"
ANALYZER_URL = "http://127.0.0.1:6002/analyze"

DB_CONN = psycopg2.connect(
    dbname="soc_db",
    user="soc_user",
    password="securepass",
    host="localhost"
)

@app.route('/events', methods=['POST'])
def receive_event():
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != f"Bearer {TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    event = request.json
    print(f"[COLLECTOR] Événement reçu: {event['type']} de {event['src_ip']}")
    
    try:
        cur = DB_CONN.cursor()
        cur.execute("""
            INSERT INTO events (event_id, type, src_ip, timestamp, details)
            VALUES (%s, %s, %s, %s, %s)
        """, (event['event_id'], event['type'], event['src_ip'], 
              event['timestamp'], event['details']))
        DB_CONN.commit()
        cur.close()
        
        print(f"[COLLECTOR] Stocké en base")
        
        requests.post(ANALYZER_URL, json=event, 
                     headers={"Authorization": f"Bearer {TOKEN}"}, 
                     timeout=3)
        
        return jsonify({"status": "ok.", "event_id": event['event_id']})
        
    except Exception as e:
        print(f"[COLLECTOR ERROR] {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("[COLLECTOR] Démarrage sur http://0.0.0.0:6001")
    app.run(host='0.0.0.0', port=6001, debug=True)
