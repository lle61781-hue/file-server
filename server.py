import os
import sys
import logging
import jwt
from datetime import datetime, timezone, timedelta
from functools import wraps
import requests
from werkzeug.security import generate_password_hash, check_password_hash

# Thư viện Flask và Extensions
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_socketio import SocketIO, join_room, leave_room, emit, disconnect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text # Cần thiết cho các truy vấn nâng cao

# --- KHỞI TẠO VÀ CẤU HÌNH ---
# Cấu hình phải được lấy từ file config hoặc biến môi trường
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_super_secret_key' # Thay đổi key này!
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CLOUDINARY_CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME')
    CLOUDINARY_API_KEY = os.environ.get('CLOUDINARY_API_KEY')
    CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')
    JWT_EXPIRATION_DELTA = timedelta(hours=24) # Token hết hạn sau 24 giờ

app = Flask(__name__)
app.config.from_object(Config)
CORS(app) 
db = SQLAlchemy(app)
sio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True, max_http_buffer_size=100_000_000) # Đặt max_http_buffer_size cho file lớn

# Cấu hình Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- MÔ HÌNH DỮ LIỆU (MODELS) ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    avatar_url = db.Column(db.String(256))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(128), index=True, unique=True, nullable=False) # Cloudinary ID
    filename = db.Column(db.String(256), nullable=False)
    folder_name = db.Column(db.String(128), default='Gốc')
    uploaded_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    uploaded_by = db.Column(db.String(64))
    
    # Thông tin theo dõi file
    last_opened_at = db.Column(db.DateTime)
    last_opened_by = db.Column(db.String(64))
    last_modified_at = db.Column(db.DateTime)
    
class FileAccessLog(db.Model):
    __tablename__ = 'file_access_logs'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    username = db.Column(db.String(64))
    action = db.Column(db.String(64))
    details = db.Column(db.Text)
    target_username = db.Column(db.String(64))
    
# --- HÀM TIỆN ÍCH ---

def create_activity_log(action, details, target_user=None):
    """Ghi log hoạt động vào DB."""
    log = ActivityLog(
        username=g.user.username if hasattr(g, 'user') else 'SYSTEM',
        action=action,
        details=details,
        target_username=target_user.username if target_user else None
    )
    db.session.add(log)
    db.session.commit()

def login_required(f):
    """Decorator xác thực JWT từ header Authorization."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Authorization header is missing'}), 401
        
        try:
            token = auth_header.split()[1]
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload.get('user_id')
            
            # Lấy user từ DB và lưu vào g.user
            user = db.session.get(User, user_id)
            if not user:
                return jsonify({'message': 'User not found'}), 401
            
            g.user = user
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'message': f'Authentication error: {e}'}), 401
            
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator yêu cầu quyền Admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'user') or not g.user.is_admin:
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return login_required(decorated_function) # Đảm bảo login_required chạy trước

# --- ROUTES CHÍNH VÀ SỬA LỖI HTTP 400 ---

@app.route('/')
def index():
    return jsonify({"status": "Server is running", "environment": os.environ.get('FLASK_ENV', 'production')})

# SỬA LỖI CHÍNH: BỔ SUNG ROUTE THIẾT YẾU VÀ ĐÃ SỬA LỖI ĐỊNH DẠNG URL

@app.route('/file/opened/<public_id>', methods=['POST'])
@login_required
def log_file_opened(public_id):
    """
    ROUTE ĐÃ SỬA LỖI: Ghi log hành động mở file và cập nhật last_opened_at/by.
    Endpoint này nhận public_id KHÔNG được mã hóa URL kép, Flask sẽ tự giải mã 1 lần.
    """
    try:
        data = request.get_json()
        filename = data.get('filename')
        
        # 1. Tìm bản ghi file bằng public_id (đã được Flask tự động giải mã 1 lần)
        file_record = db.session.query(File).filter_by(public_id=public_id).first()
        
        if not file_record:
            logger.warning(f"File not found for public_id: {public_id}")
            # Trả về 404 nếu không tìm thấy, đây là lý do phổ biến thứ 2 gây lỗi 400
            return jsonify({'message': 'File không tìm thấy (ID không hợp lệ).'}), 404

        # 2. Cập nhật trạng thái mở file
        file_record.last_opened_at = datetime.now(timezone.utc)
        file_record.last_opened_by = g.user.username
        
        # 3. Ghi log truy cập chi tiết
        access_log = FileAccessLog(file_id=file_record.id, user_id=g.user.id)
        db.session.add(access_log)
        
        # 4. Ghi log hoạt động chung
        create_activity_log('OPEN_FILE', f'Mở file: {filename}', target_user=g.user)
        
        db.session.commit()
        
        return jsonify({'message': f'Đã ghi nhận mở file: {filename}'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error logging file open for {public_id}: {e}", exc_info=True)
        # Trả về 500 nếu là lỗi server nội bộ
        return jsonify({'message': f'Lỗi server nội bộ: {e}'}), 500

# --- CÁC ROUTES CẦN THIẾT KHÁC (Cần thiết cho Client hoạt động) ---

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = db.session.query(User).filter_by(username=username).first()
    
    if user and user.check_password(password):
        # Tạo JWT
        token_payload = {
            'user_id': user.id,
            'username': user.username,
            'exp': datetime.now(timezone.utc) + app.config['JWT_EXPIRATION_DELTA']
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'message': 'Login successful', 
            'token': token,
            'user_id': user.id,
            'username': user.username,
            'is_admin': user.is_admin,
            'avatar_url': user.avatar_url
        }), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/download', methods=['POST'])
@login_required
def download_file_route():
    # Giả định logic tạo URL Cloudinary và trả về (Cần cài đặt thư viện Cloudinary)
    try:
        # TÍCH HỢP VỚI Cloudinary thực tế (Đoạn này cần setup Cloudinary API)
        # Ví dụ đơn giản:
        data = request.get_json()
        public_id = data.get('public_id')
        
        # public_id = public_id.replace('/', '%2F') # Cloudinary cần ID mã hóa cho URL
        
        # SỬ DỤNG PUBLIC ID để tạo ra URL TẢI XUỐNG CÓ DẤU THỜI GIAN/CHỮ KÝ
        # Ví dụ: Mở file (view/download)
        download_url = f"https://res.cloudinary.com/{app.config['CLOUDINARY_CLOUD_NAME']}/raw/upload/{public_id}" 
        
        create_activity_log('DOWNLOAD_FILE', f'Tải file: {public_id}', target_user=g.user)
        
        return jsonify({'download_url': download_url}), 200
    except Exception as e:
        logger.error(f"Error generating download URL: {e}")
        return jsonify({'message': 'Lỗi tạo URL tải xuống.'}), 500

# THÊM CÁC ROUTES KHÁC CỦA BẠN VÀO ĐÂY (upload, file/update, admin, chat history...)

# --- KHỞI TẠO DB VÀ CHẠY APP ---

@app.cli.command('init_db')
def init_db_command():
    """Tạo DB và tạo Admin User mặc định."""
    with app.app_context():
        db.create_all()
        if not db.session.query(User).filter_by(username='admin').first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print("Database initialized and 'admin' user created (password: admin).")
        else:
            print("Database already initialized.")

if __name__ == '__main__':
    # THAY THẾ bằng gunicorn hoặc môi trường deploy thực tế (Render)
    # Ví dụ: gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 server:app 
    with app.app_context():
        db.create_all() # Đảm bảo DB được tạo lần đầu
        # Nếu chưa có admin, tạo admin mặc định
        if not db.session.query(User).filter_by(username='admin').first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            logger.info("Admin user created.")

    sio.run(app, host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)
