from flask import Flask, request, jsonify, send_from_directory
import jwt
import datetime
import os

app = Flask(__name__)

# CTF Flag (hidden in admin panel)
CTF_FLAG = 'FLAG{jwt_h4ck_w1th_w34k_s3cr3t_k3y!}'

# Deliberately weak secret key
SECRET_KEY = 'verysecurekey123'

# Serve the HTML file
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# Intentionally vulnerable JWT authentication
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    # Extremely weak authentication (hardcoded credentials)
    if username == 'admin' and password == 'password':
        # Create a JWT with no admin access
        token = jwt.encode({
            'username': username,
            'admin': False,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')
        
        return jsonify({'token': token})
    
    return jsonify({'message': 'Invalid credentials'}), 401

# Protected admin route with vulnerable authentication
@app.route('/admin', methods=['GET'])
def admin_panel():
    token = request.headers.get('Authorization')
    
    try:
        # Weak JWT verification
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        
        if payload.get('admin', False):
            return jsonify({
                'message': 'Admin Access Granted!',
                'flag': CTF_FLAG
            })
        
        return jsonify({'message': 'Access denied. Admin privileges required.'}), 403
    
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)