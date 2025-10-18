import os
import sys
import json
import logging
import requests
from datetime import datetime, timezone

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, leave_room, emit, disconnect
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

# --- KHỞI TẠO VÀ CẤU HÌNH CƠ BẢN ---
# Giả định các hàm/class/biến này đã được định nghĩa trong môi trường của bạn
# Ví dụ: from models import db, User, File, FileAccessLog, Message, ActivityLog 
# from utils import login_required, create_activity_log, logger
# 
# THAY THẾ CHÚ THÍCH NÀY BẰNG CÁC DÒNG IMPORT THỰC TẾ CỦA BẠN!
# -------------------------------------------------------------
class MockDB:
    """Mock database session for demonstration."""
    def add(self, obj): pass
    def commit(self): pass
    def rollback(self): pass
    
class MockUser:
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin
        
class MockFile:
    def __init__(self, id, public_id, user_id, filename):
        self.id = id
        self.public_id = public_id
        self.user_id = user_id
        self.filename = filename
        self.last_opened_at = None
        self.last_opened_by = None

class MockQuery:
    def __init__(self, items):
        self.items = items
    def filter_by(self, public_id=None):
        if public_id:
            for item in self.items:
                if item.public_id == public_id:
                    return self
        return self
    def first(self):
        return self.items[0] if self.items else None

# Mocking database objects and functions
db = MockDB()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Giả định User hiện tại (current_user)
class CurrentUser:
    def __init__(self):
        self.id = None
        self.username = None
        self.is_admin = False
current_user = CurrentUser()

# Giả định mô hình File và truy vấn (để đoạn code sửa lỗi hoạt động)
class File:
    query = MockQuery([]) # Thay thế bằng db.session.query(File) thực tế
    
class FileAccessLog:
    def __init__(self, **kwargs): pass

def create_activity_log(action, details, target_user_id=None):
    logger.info(f"LOG: {action} - {details} (User: {current_user.username})")

def login_required(f):
    """Giả định decorator xác thực JWT."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Giả định quá trình xác thực JWT đã chạy và đặt thông tin user vào `current_user`
        global current_user
        current_user.id = 1 
        current_user.username = "admin"
        current_user.is_admin = True
        return f(*args, **kwargs)
    return decorated_function
# -------------------------------------------------------------
# KẾT THÚC KHU VỰC GIẢ ĐỊNH (END MOCK AREA)
# -------------------------------------------------------------


# Khởi tạo Flask App
app = Flask(__name__)
CORS(app) # Cho phép Cross-Origin Requests
# app.config.from_object('config') # Giả định bạn có config.py
# db.init_app(app) # Giả định kết nối DB đã có

# SocketIO
# sio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)
# Sẽ không khởi tạo SIO trong code này vì không cần thiết cho route sửa lỗi.


# --- SỬA LỖI HTTP 400: BỔ SUNG ENDPOINT GHI NHẬN LỊCH SỬ MỞ FILE ---

@app.route('/file/opened/<public_id>', methods=['POST'])
@login_required
def log_file_opened(public_id):
    """
    ROUTE ĐÃ SỬA: Ghi log hành động mở file và cập nhật last_opened_at/by.
    Endpoint này nhận public_id KHÔNG được mã hóa URL từ Client.
    """
    try:
        data = request.get_json()
        filename = data.get('filename')
        
        # 1. Tìm bản ghi file bằng public_id
        # Sửa lỗi: Lấy public_id trực tiếp từ đường dẫn (đã được Flask tự động giải mã).
        # TÍCH HỢP VỚI DB THỰC TẾ CỦA BẠN:
        # file_record = db.session.query(File).filter_by(public_id=public_id).first()
        
        # Ví dụ Mock:
        file_record = MockFile(id=1, public_id=public_id, user_id=1, filename=filename) 
        
        if not file_record:
            return jsonify({'message': 'File không tìm thấy.'}), 404

        # 2. Cập nhật trạng thái mở file
        file_record.last_opened_at = datetime.now(timezone.utc)
        file_record.last_opened_by = current_user.username
        
        # 3. Ghi log truy cập
        access_log = FileAccessLog(file_id=file_record.id, user_id=current_user.id)
        db.add(access_log) # Dùng db.add(access_log) và db.commit() thực tế
        
        # 4. Ghi log hoạt động chung
        create_activity_log('OPEN_FILE', f'Mở file: {filename}', target_user_id=file_record.user_id)
        
        db.commit() # Dùng db.session.commit() thực tế
        
        return jsonify({'message': f'Đã ghi nhận mở file: {filename}'}), 200
        
    except Exception as e:
        logger.error(f"Error logging file open for {public_id}: {e}")
        db.rollback() # Dùng db.session.rollback() thực tế
        # Trả về lỗi 500 nếu là lỗi server nội bộ
        return jsonify({'message': f'Lỗi server nội bộ: {e}'}), 500

# --- CÁC ROUTES QUAN TRỌNG KHÁC (Chỉ hiển thị placeholder) ---

@app.route('/login', methods=['POST'])
def login():
    # Giả định logic login ở đây
    return jsonify({'token': 'mock_token', 'user_id': 1, 'username': 'admin', 'is_admin': True})

@app.route('/download', methods=['POST'])
@login_required
def download_file_route():
    # Giả định logic tạo URL Cloudinary và trả về
    return jsonify({'download_url': 'https://mock-cloudinary-url.com/file.doc'})

@app.route('/file/update', methods=['POST'])
@login_required
def update_file():
    # Giả định logic cập nhật file sync
    return jsonify({'message': 'File updated', 'version': 1})
    
@app.route('/files/in-folder', methods=['GET'])
@login_required
def get_files_in_folder():
    # Giả định logic tải danh sách files
    return jsonify({'files': []})
    
# Thêm các routes khác của bạn vào đây (upload, delete, admin, chat history...)

if __name__ == '__main__':
    # THAY THẾ bằng gunicorn hoặc môi trường deploy thực tế (Render)
    app.run(debug=True, port=5000)
