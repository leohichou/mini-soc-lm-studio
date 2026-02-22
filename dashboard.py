from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import psycopg2
import threading
import time
import eventlet
eventlet.monkey_patch() 

from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'soc_dashboard_secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

def get_db():
    try:
        return psycopg2.connect(
            dbname="soc_db",
            user="soc_user",
            password="securepass",
            host="localhost"
        )
    except Exception as e:
        print(f"[DASHBOARD DB ERROR] {e}")
        return None

@app.route('/')
def index():
    print(f"[DASHBOARD] Page demandée")
    return render_template('index.html')

@app.route('/api/events')
def get_events_api():
    conn = get_db()
    if not conn:
        return jsonify([])
    
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT e.id, e.type, e.src_ip, e.timestamp, 
                   a.severity, a.category, a.recommended_action, a.action_taken
            FROM events e
            LEFT JOIN analyses a ON e.event_id = a.event_id
            ORDER BY e.timestamp DESC LIMIT 50
        """)
        events = []
        for row in cur.fetchall():
            events.append([
                row[0],
                row[1],
                row[2],
                row[3].isoformat() if isinstance(row[3], datetime) else str(row[3]),
                row[4] or '-',
                row[5] or '-',
                row[6] or '-',
                row[7] or 'pending'
            ])
        cur.close()
        conn.close()
        return jsonify(events)
    except Exception as e:
        print(f"[DASHBOARD API ERROR] {e}")
        return jsonify([])

def poll_events():
    print("[DASHBOARD] Poller démarré")
    while True:
        time.sleep(2)
        try:
            conn = get_db()
            if not conn:
                continue
                
            cur = conn.cursor()
            cur.execute("""
                SELECT e.id, e.type, e.src_ip, e.timestamp, 
                       a.severity, a.category, a.recommended_action, a.action_taken
                FROM events e
                LEFT JOIN analyses a ON e.event_id = a.event_id
                ORDER BY e.timestamp DESC LIMIT 50
            """)
            events = []
            for row in cur.fetchall():
                events.append([
                    row[0],
                    row[1],
                    row[2],
                    row[3].isoformat() if isinstance(row[3], datetime) else str(row[3]),
                    row[4] or '-',
                    row[5] or '-',
                    row[6] or '-',
                    row[7] or 'pending'
                ])
            cur.close()
            conn.close()
            
            socketio.emit('update', {'events': events})
            print(f"[DASHBOARD] Émission: {len(events)} événements")
            
        except Exception as e:
            print(f"[DASHBOARD POLL ERROR] {e}")

@socketio.on('connect')
def handle_connect():
    print(f"[DASHBOARD] Client connecté")
    socketio.emit('welcome', {'message': 'Bienvenue sur le SOC Dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"[DASHBOARD] Client déconnecté")

if __name__ == '__main__':
    print("[DASHBOARD] Démarrage sur http://0.0.0.0:5000")
    
    threading.Thread(target=poll_events, daemon=True).start()
    
    socketio.run(
        app, 
        host='0.0.0.0',
        port=5000, 
        debug=False,  # Changez à False pour moins de logs
        allow_unsafe_werkzeug=True
    )
