from flask import Flask, request, jsonify
import psycopg2
import subprocess

app = Flask(__name__)
TOKEN = "SECRET_TOKEN_SOC123"

DB_CONN = psycopg2.connect(
    dbname="soc_db",
    user="soc_user",
    password="securepass",
    host="localhost"
)

@app.route('/respond', methods=['POST'])
def respond():
    if request.headers.get('Authorization') != f"Bearer {TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    event = request.json
    action = event.get('recommended_action', 'ignore')
    action_taken = "ignored"
    
    print(f"[RESPONDER] Action: {action} pour IP {event['src_ip']}")
    
    if action == "block_ip":
        ip = event['src_ip']
        try:
            result = subprocess.run(["sudo", "ufw", "status", "numbered"], 
                                  capture_output=True, text=True)
            if ip not in result.stdout:
                subprocess.run(["sudo", "ufw", "insert", "1", "deny", "from", ip], 
                             check=True)
                action_taken = "blocked"
                print(f"[RESPONDER] IP bloquée: {ip}")
            else:
                action_taken = "already_blocked"
                print(f"[RESPONDER] IP déjà bloquée: {ip}")
        except Exception as e:
            print(f"[RESPONDER] Erreur: {e}")
            action_taken = "block_failed"
    
    elif action == "create_ticket":
        print(f"[RESPONDER] Ticket créé pour {event['event_id']}")
        action_taken = "ticket_created"
    
    try:
        cur = DB_CONN.cursor()
        cur.execute("""
            UPDATE analyses SET action_taken = %s 
            WHERE event_id = %s
        """, (action_taken, event['event_id']))
        DB_CONN.commit()
        cur.close()
    except Exception as e:
        print(f"[RESPONDER] Erreur DB: {e}")
    
    return jsonify({"status": action_taken})

if __name__ == '__main__':
    print("[RESPONDER] Démarrage sur http://0.0.0.0:6003")
    app.run(host='0.0.0.0', port=6003, debug=True)
