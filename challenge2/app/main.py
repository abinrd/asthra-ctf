from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash
import sqlite3
import os
import json
import base64

app = Flask(__name__)
app.secret_key = os.urandom(24)

def init_db():
    # Changed database path to /data directory
    conn = sqlite3.connect('/data/database.db')

    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS secrets
                 (id INTEGER PRIMARY KEY, data TEXT)''')
    # Insert some fake data
    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', ?)",
             (generate_password_hash('not_the_real_password'),))
    c.execute("INSERT OR IGNORE INTO secrets (id, data) VALUES (1, ?)",
             (base64.b64encode(b'CTF{n0t_th3_r34l_fl4g}').decode(),))
    c.execute("""INSERT OR IGNORE INTO secrets (id, data) VALUES 
                 (1337, 'CTF{5ql1_15_n0t_d34d_y3t}')""")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Intentionally vulnerable to SQLi
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        result = c.execute(query).fetchone()
        if result:
            # Add fake response header to mislead
            resp = jsonify({'status': 'error', 'message': 'Invalid credentials'})
            resp.headers['X-Debug'] = base64.b64encode(b'Check /admin_panel.php').decode()
            return resp
        return jsonify({'status': 'error', 'message': 'User not found'})
    except sqlite3.Error as e:
        return jsonify({'status': 'error', 'message': str(e)})
    finally:
        conn.close()

@app.route('/admin_panel.php')
def fake_admin():
    # Fake admin panel with obfuscated JS
    return render_template('admin.html')

@app.route('/api/get_secret', methods=['POST'])
def get_secret():
    data = request.get_json()
    secret_id = data.get('id', 1)
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        result = c.execute("SELECT data FROM secrets WHERE id = ?", (secret_id,)).fetchone()
        if result:
            return jsonify({'data': result[0]})
        return jsonify({'error': 'Not found'})
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)