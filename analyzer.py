from flask import Flask, request, jsonify
import requests
import psycopg2
import json
import re
import time

app = Flask(__name__)
TOKEN = "SECRET_TOKEN_SOC123"
RESPONDER_URL = "http://127.0.0.1:6003/respond"
LLM_URL = "http://127.0.0.1:1234/v1/chat/completions"

DB_CONN = psycopg2.connect(
    dbname="soc_db",
    user="soc_user", 
    password="securepass",
    host="localhost"
)

def force_json_response(text):
    """Force une réponse JSON, même si Gemma est bavarde."""
    text = text.strip()
    
    text = re.sub(r'```json|```', '', text)
    
    start = text.find('{')
    end = text.rfind('}') + 1
    
    if start != -1 and end != 0:
        json_str = text[start:end]
        try:
            data = json.loads(json_str)
            required = ["severity", "category", "recommended_action"]
            if all(key in data for key in required):
                return data
        except:
            pass
    
    if "Failed password" in text or "ssh" in text.lower() or "brute" in text.lower():
        return {"severity": "High", "category": "brute_force", "recommended_action": "block_ip"}
    elif "scan" in text.lower() or "port" in text.lower():
        return {"severity": "Medium", "category": "port_scan", "recommended_action": "investigate"}
    elif "ddos" in text.lower() or "flood" in text.lower():
        return {"severity": "High", "category": "ddos", "recommended_action": "block_ip"}
    else:
        return {"severity": "Medium", "category": "suspicious", "recommended_action": "create_ticket"}

@app.route('/analyze', methods=['POST'])
def analyze():
    if request.headers.get('Authorization') != f"Bearer {TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    event = request.json
    print(f"\n[ANALYZER] === NOUVEL ÉVÉNEMENT ===")
    print(f"Type: {event['type']}")
    print(f"IP: {event['src_ip']}")
    print(f"Détails: {event['details'][:100]}...")
    
    prompt = f"""SYSTÈME: Tu es un analyseur de sécurité SOC. Tu réponds UNIQUEMENT avec du JSON valide.
RÈGLE ABSOLUE: Pas de texte, pas d'explications, pas de ```json, juste le JSON pur.

ÉVÉNEMENT À ANALYSER:
{event['details']}

RÉPONDS UNIQUEMENT AVEC CE FORMAT JSON (rien d'autre):
{{
  "severity": "High",
  "category": "brute_force",
  "recommended_action": "block_ip"
}}

Choisis parmi:
- severity: High, Medium, Low
- category: brute_force, port_scan, ddos, suspicious, other
- recommended_action: block_ip, investigate, create_ticket, ignore

JSON DE RÉPONSE (obligatoire):"""
    
    payload = {
        "model": "local-model",
        "messages": [
            {
                "role": "system",
                "content": "Tu réponds UNIQUEMENT avec du JSON valide. Pas de texte supplémentaire. Format: {\"severity\": \"...\", \"category\": \"...\", \"recommended_action\": \"...\"}"
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1,
        "max_tokens": 150,
        "stream": False
    }
    
    start_time = time.time()
    llm_raw_response = ""
    analysis = {"severity": "Medium", "category": "unknown", "recommended_action": "ignore"}
    
    try:
        print(f"[ANALYZER] Envoi à LM Studio (timeout: 30s)...")
        
        resp = requests.post(LLM_URL, json=payload, timeout=30)
        
        elapsed = time.time() - start_time
        print(f"[ANALYZER] Réponse en {elapsed:.1f}s - Status: {resp.status_code}")
        
        if resp.status_code == 200:
            result = resp.json()
            llm_raw_response = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            
            print(f"[ANALYZER] Réponse brute (premiers 200 chars):")
            print("-" * 50)
            print(llm_raw_response[:200])
            print("-" * 50)
            
            analysis = force_json_response(llm_raw_response)
            
            print(f"[ANALYZER] Analyse extraite: {analysis}")
            
        else:
            print(f"[ANALYZER] Erreur HTTP {resp.status_code}")
            print(f"Réponse: {resp.text[:200]}")
            
            if event['type'] == 'ssh_failed':
                analysis = {"severity": "High", "category": "brute_force", "recommended_action": "block_ip"}
            elif event['type'] == 'port_scan':
                analysis = {"severity": "Medium", "category": "port_scan", "recommended_action": "investigate"}
            else:
                analysis = {"severity": "Medium", "category": "suspicious", "recommended_action": "create_ticket"}
                
    except requests.exceptions.Timeout:
        print(f"[ANALYZER] TIMEOUT après {time.time() - start_time:.1f}s")
        print("[ANALYZER] LM Studio trop lent, utilisation de règles prédéfinies")
        
        if "Failed password" in event['details'] or event['type'] == 'ssh_failed':
            analysis = {"severity": "High", "category": "brute_force", "recommended_action": "block_ip"}
        elif "refused" in event['details'] or event['type'] == 'port_scan':
            analysis = {"severity": "Medium", "category": "port_scan", "recommended_action": "investigate"}
        else:
            analysis = {"severity": "Medium", "category": "suspicious", "recommended_action": "create_ticket"}
            
        llm_raw_response = "TIMEOUT - Règles prédéfinies utilisées"
        
    except Exception as e:
        print(f"[ANALYZER] Erreur: {type(e).__name__}: {e}")
        analysis = {"severity": "Medium", "category": "unknown", "recommended_action": "ignore"}
        llm_raw_response = f"Erreur: {str(e)}"
    
    analysis.setdefault("severity", "Medium")
    analysis.setdefault("category", "unknown")
    analysis.setdefault("recommended_action", "ignore")
    
    try:
        cur = DB_CONN.cursor()
        cur.execute("""
            INSERT INTO analyses (event_id, severity, category, recommended_action, llm_response)
            VALUES (%s, %s, %s, %s, %s)
        """, (event['event_id'], analysis['severity'], analysis['category'],
              analysis['recommended_action'], llm_raw_response[:1000]))
        DB_CONN.commit()
        cur.close()
        print(f"[ANALYZER] Stocké en base")
    except Exception as e:
        print(f"[ANALYZER] Erreur DB: {e}")
    
    event.update(analysis)
    try:
        resp = requests.post(RESPONDER_URL, json=event,
                           headers={"Authorization": f"Bearer {TOKEN}"},
                           timeout=5)
        print(f"[ANALYZER] Réponse du responder: {resp.status_code}")
    except Exception as e:
        print(f"[ANALYZER] Erreur envoi responder: {e}")
    
    print(f"[ANALYZER] === ANALYSE TERMINÉE ===")
    print(f"Résultat: {analysis}\n")
    
    return jsonify({"status": "analyzed", "analysis": analysis})

if __name__ == '__main__':
    print("[ANALYZER] Démarrage sur http://0.0.0.0:6002")
    print("[ANALYZER] Prompt strict activé - Timeout: 30s")
    app.run(host='0.0.0.0', port=6002, debug=True)
