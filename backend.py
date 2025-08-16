# Import các thư viện cần thiết
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

# Thư viện của Google để xác thực token
from google.oauth2 import id_token
from google.auth.transport import requests

# --- CẤU HÌNH ---
# !!! QUAN TRỌNG: Thay thế bằng Client ID bạn đã lấy từ Google Cloud Console !!!
GOOGLE_CLIENT_ID = "359227934987-7pl8fm1tf1r6b3r4v77dppj1pvtiehpl.apps.googleusercontent.com"

# Khởi tạo Flask App
app = Flask(__name__)
CORS(app)  # Cho phép Frontend (chạy ở địa chỉ khác) có thể gọi tới Backend

# --- CƠ SỞ DỮ LIỆU ---
def init_db():
    """Hàm để tạo database và bảng users nếu chưa có."""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Tạo bảng users với các cột cần thiết
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

# --- CÁC ĐƯỜNG DẪN (API ENDPOINTS) ---

@app.route('/register', methods=['POST'])
def register():
    """Endpoint để xử lý đăng ký tài khoản thông thường."""
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Vui lòng điền đầy đủ thông tin!'}), 400

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Kiểm tra xem username hoặc email đã tồn tại chưa
    cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
    if cursor.fetchone():
        conn.close()
        return jsonify({'message': 'Tên đăng nhập hoặc email đã tồn tại!'}), 409

    # Mã hóa mật khẩu trước khi lưu
    password_hash = generate_password_hash(password)

    # Lưu người dùng mới vào database
    cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', 
                   (username, email, password_hash))
    
    conn.commit()
    conn.close()

    return jsonify({'message': 'Đăng ký thành công!'}), 201

@app.route('/login', methods=['POST'])
def login():
    """Endpoint để xử lý đăng nhập tài khoản thông thường."""
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Vui lòng điền đầy đủ thông tin!'}), 400

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()

    # user[3] là cột password_hash
    if user and check_password_hash(user[3], password):
        # Trong ứng dụng thực tế, bạn sẽ tạo session hoặc JWT token ở đây
        return jsonify({'message': f'Đăng nhập thành công! Chào mừng {user[1]}!'}), 200
    else:
        return jsonify({'message': 'Email hoặc mật khẩu không chính xác!'}), 401

@app.route('/login-google', methods=['POST'])
def login_google():
    """Endpoint để nhận và xác thực Google ID Token."""
    data = request.json
    token = data.get('token')

    if not token:
        return jsonify({'message': 'ID Token không được để trống!'}), 400

    try:
        # Xác thực token với máy chủ của Google
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)

        # Lấy thông tin người dùng từ token
        google_id = idinfo['sub']
        email = idinfo['email']
        name = idinfo['name']
        picture = idinfo['picture']

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Kiểm tra xem người dùng này đã tồn tại trong DB chưa
        cursor.execute('SELECT * FROM users WHERE google_id = ? OR email = ?', (google_id, email))
        user = cursor.fetchone()

        if user:
            # Nếu đã tồn tại, chỉ cần đăng nhập cho họ
            message = f'Đăng nhập bằng Google thành công! Chào mừng trở lại {user[1]}!'
        else:
            # Nếu chưa tồn tại, tạo tài khoản mới
            cursor.execute('''
                INSERT INTO users (username, email, google_id, profile_picture) 
                VALUES (?, ?, ?, ?)
            ''', (name, email, google_id, picture))
            conn.commit()
            message = f'Tài khoản đã được tạo! Chào mừng {name}!'
        
        conn.close()
        
        return jsonify({'message': message, 'user_info': idinfo}), 200

    except ValueError as e:
        return jsonify({'message': f'Token không hợp lệ: {e}'}), 401
    except Exception as e:
        return jsonify({'message': f'Lỗi máy chủ: {e}'}), 500

# --- KHỞI CHẠY SERVER ---
if __name__ == '__main__':
    init_db()  # Chạy hàm tạo DB khi khởi động server
    # Chạy server ở cổng 5000, có thể truy cập từ mọi địa chỉ trong mạng
    app.run(host='0.0.0.0', port=5000, debug=True)
