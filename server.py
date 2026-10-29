from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
DB_FILE = "keys.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys (
                    key TEXT PRIMARY KEY,
                    expiry TEXT,
                    hwid TEXT,
                    banned INTEGER DEFAULT 0
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    hwid TEXT,
                    pc_name TEXT,
                    last_seen TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

@app.route('/validate', methods=['POST'])
def validate():
    data = request.json
    key = data.get('key', '').upper()
    hwid = data.get('hwid', '')
    pc_name = data.get('pc_name', 'Unknown')

    if key == "ULTRA":
        return jsonify({"status": "owner"})

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT expiry, hwid, banned FROM keys WHERE key=?", (key,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"status": "invalid", "msg": "Key not found"})
        
    expiry, db_hwid, banned = row
    
    if banned == 1:
        conn.close()
        return jsonify({"status": "banned", "msg": "Key is banned"})
        
    if expiry.lower() != "lifetime":
        try:
            if datetime.now() > datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S"):
                conn.close()
                return jsonify({"status": "expired", "msg": f"Expired on {expiry}"})
        except: pass
        
    if db_hwid == "" or db_hwid is None:
        c.execute("UPDATE keys SET hwid=? WHERE key=?", (hwid, key))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "msg": "Key locked to your PC!"})
        
    elif db_hwid != hwid:
        conn.close()
        return jsonify({"status": "mismatch", "msg": "Key locked to another PC"})
        
    else:
        c.execute("SELECT * FROM users WHERE hwid=?", (hwid,))
        if c.fetchone():
            c.execute("UPDATE users SET last_seen=?, pc_name=? WHERE hwid=?", (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), pc_name, hwid))
        else:
            c.execute("INSERT INTO users VALUES (?, ?, ?)", (hwid, pc_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "msg": "Access Granted"})

@app.route('/api/key_from_hwid', methods=['POST'])
def key_from_hwid():
    data = request.json
    hwid = data.get('hwid', '')
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT key FROM keys WHERE hwid=? AND banned=0", (hwid,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return jsonify({"status": "success", "key": row[0]})
    return jsonify({"status": "not_found"})

# --- OWNER ROUTES ---
@app.route('/owner/reset_hwid', methods=['POST'])
def reset_hwid():
    if request.json.get('auth') != "ULTRA": return jsonify({"status": "denied"})
    key = request.json.get('key', '').upper()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE keys SET hwid='' WHERE key=?", (key,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/owner/ban', methods=['POST'])
def ban_key():
    if request.json.get('auth') != "ULTRA": return jsonify({"status": "denied"})
    key = request.json.get('key', '').upper()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE keys SET banned=1 WHERE key=?", (key,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/owner/users', methods=['GET'])
def get_users():
    if request.args.get('auth') != "ULTRA": return jsonify({"status": "denied"})
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    rows = c.fetchall()
    conn.close()
    users = [{"hwid": r[0], "pc_name": r[1], "last_seen": r[2]} for r in rows]
    return jsonify({"status": "success", "users": users})

@app.route('/owner/generate', methods=['POST'])
def gen_key():
    if request.json.get('auth') != "ULTRA": return jsonify({"status": "denied"})
    days = int(request.json.get('days', 7))
    expiry = "Lifetime" if days == 0 else (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    new_key = str(uuid.uuid4()).replace('-', '').upper()[:16]
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO keys (key, expiry) VALUES (?, ?)", (new_key, expiry))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "key": new_key, "expiry": expiry})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
