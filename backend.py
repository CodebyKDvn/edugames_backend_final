# GOOGLE_CLIENT_ID = "359227934987-7pl8fm1tf1r6b3r4v77dppj1pvtiehpl.apps.googleusercontent.com"
# Import thêm các thư viện cần thiết từ Flask
# Import thêm các thư viện cần thiết từ Flask
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests

# --- CẤU HÌNH ---
# !!! QUAN TRỌNG: Thay thế bằng Client ID bạn đã lấy từ Google Cloud Console !!!
GOOGLE_CLIENT_ID = "359227934987-7pl8fm1tf1r6b3r4v77dppj1pvtiehpl.apps.googleusercontent.com"

# Khởi tạo Flask App, chỉ định thư mục templates
app = Flask(__name__, template_folder='templates')

# !!! === SỬA LỖI CORS NẰM Ở ĐÂY === !!!
# Cấu hình CORS để cho phép yêu cầu từ mọi nguồn và hỗ trợ credentials
CORS(app, supports_credentials=True)

# !!! QUAN TRỌNG: Cần có SECRET_KEY để sử dụng session an toàn !!!
app.secret_key = os.urandom(24) 

# --- CƠ SỞ DỮ LIỆU ---
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            google_id TEXT UNIQUE,
            profile_picture TEXT
        )
    ''')
    conn.commit()
    conn.close()

# --- CÁC ROUTE HIỂN THỊ TRANG (VIEW) ---

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('account'))
    return render_template('index.html')

@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    return render_template('account.html')

# --- CÁC API ENDPOINTS ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username, email, password = data.get('username'), data.get('email'), data.get('password')
    if not all([username, email, password]):
        return jsonify({'message': 'Vui lòng điền đầy đủ thông tin!'}), 400
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
    if cursor.fetchone():
        conn.close()
        return jsonify({'message': 'Tên đăng nhập hoặc email đã tồn tại!'}), 409
    password_hash = generate_password_hash(password)
    cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', (username, email, password_hash))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Đăng ký thành công!'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email, password = data.get('email'), data.get('password')
    if not email or not password:
        return jsonify({'message': 'Vui lòng điền đầy đủ thông tin!'}), 400
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    if user and user['password_hash'] and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        return jsonify({'message': f'Đăng nhập thành công! Chào mừng {user["username"]}!'}), 200
    else:
        return jsonify({'message': 'Email hoặc mật khẩu không chính xác!'}), 401

@app.route('/api/login-google', methods=['POST'])
def login_google():
    data = request.json
    token = data.get('token')
    if not token: return jsonify({'message': 'ID Token không được để trống!'}), 400
    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        google_id, email, name, picture = idinfo['sub'], idinfo['email'], idinfo['name'], idinfo['picture']
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE google_id = ? OR email = ?', (google_id, email))
        user = cursor.fetchone()
        if not user:
            cursor.execute('INSERT INTO users (username, email, google_id, profile_picture) VALUES (?, ?, ?, ?)',(name, email, google_id, picture))
            conn.commit()
            cursor.execute('SELECT * FROM users WHERE google_id = ?', (google_id,))
            user = cursor.fetchone()
        
        session['user_id'] = user['id']
        conn.close()
        return jsonify({'message': f'Đăng nhập bằng Google thành công! Chào mừng {user["username"]}!'}), 200
    except ValueError:
        return jsonify({'message': 'Token không hợp lệ.'}), 401

@app.route('/api/user')
def get_user_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, profile_picture FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify(dict(user))
    else:
        session.clear()
        return jsonify({'error': 'User not found'}), 404

@app.route('/api/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# --- KHỞI CHẠY SERVER ---
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)

