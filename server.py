import eventlet
# Dòng này phải là dòng đầu tiên sau import os/sys (nếu có)
eventlet.monkey_patch() 

import os, click, cloudinary, cloudinary.uploader, cloudinary.api
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
from flask.cli import with_appcontext 
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, or_, not_
from sqlalchemy.sql import func 
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps
from flask_socketio import SocketIO, emit
import uuid
import logging
import requests
import time
import urllib.parse 

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-fallback-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Tăng giới hạn tải lên của Flask lên 256MB (giải pháp cho vấn đề 413)
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024 

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager()
login_manager.init_app(app)

# Cấu hình Cloudinary (cần thiết cho chức năng tải file)
CLOUDINARY_CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME')
CLOUDINARY_API_KEY = os.environ.get('CLOUDINARY_API_KEY')
CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')

if CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET:
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET
    )
    print("Cloudinary configured.")
else:
    print("WARNING: Cloudinary environment variables not set. File uploads will fail.")

# Biến toàn cục để lưu trữ SID của người dùng đang online (dùng cho SocketIO)
online_users = {}

# --- HẰNG SỐ ADMIN MẶC ĐỊNH ---
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = '123'
# ------------------------------

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.now)
    is_online = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)  # <<< TRƯỜNG MỚI CHO ADMIN

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'registration_date': self.registration_date.isoformat(),
            'is_online': self.is_online,
            'is_admin': self.is_admin # Thêm trường Admin
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(1024), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    is_read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'sender': self.sender.username,
            'message': self.content,
            'timestamp': self.timestamp.isoformat(),
            'is_read': self.is_read
        }

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False) # e.g., 'LOGIN', 'SEND_MESSAGE', 'UPLOAD_FILE'
    details = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# --- LOGIN MANAGER CONFIG ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_activity_log(action, details, target_user_id=None):
    if not current_user.is_authenticated:
        return # Bỏ qua log nếu không có user
        
    log = ActivityLog(
        user_id=current_user.id,
        action=action,
        details=details,
        target_user_id=target_user_id
    )
    db.session.add(log)
    db.session.commit()

# --- CUSTOM DECORATORS ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'message': 'Chức năng yêu cầu quyền Admin.'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- FLASK CLI COMMANDS (Tạo Admin tự động) ---
@app.cli.command('init-db')
@with_appcontext
def init_db_command():
    """Tạo các bảng cơ sở dữ liệu và thêm tài khoản Admin mặc định."""
    print("Đang tạo bảng database...")
    db.create_all()
    print("Database tables created.")
    
    # Kiểm tra và tạo tài khoản Admin
    admin_exists = db.session.execute(db.select(User).filter_by(username=ADMIN_USERNAME)).scalar_one_or_none()
    
    if not admin_exists:
        print(f"Không tìm thấy Admin. Đang tạo tài khoản Admin: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
        admin = User(username=ADMIN_USERNAME, is_admin=True)
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
        print("Tạo tài khoản Admin thành công!")
    else:
        print(f"Tài khoản Admin ('{ADMIN_USERNAME}') đã tồn tại. Bỏ qua việc tạo.")

# --- API ENDPOINTS ---

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        login_user(user)
        # Cập nhật trạng thái online
        user.is_online = True
        db.session.commit()
        # Log hoạt động
        create_activity_log('LOGIN', f'Đăng nhập thành công')
        
        # Trả về JWT hoặc data + token placeholder cho client Flutter
        # (Sử dụng ID người dùng làm token cho SocketIO, vì Flask-Login không tạo JWT)
        return jsonify({
            'message': 'Đăng nhập thành công',
            'access_token': str(uuid.uuid4()), # Đây chỉ là token placeholder cho client Flutter
            'user_data': user.to_dict()
        }), 200
    
    return jsonify({'message': 'Tên người dùng hoặc mật khẩu không đúng.'}), 401

# @app.route('/register', methods=['POST'])
# def register():
#     """ĐÃ BỊ VÔ HIỆU HÓA theo yêu cầu, chỉ Admin mới được tạo người dùng."""
#     return jsonify({'message': 'Đăng ký đã bị vô hiệu hóa. Vui lòng liên hệ Admin.'}), 403

@app.route('/admin/create_user', methods=['POST'])
@admin_required
def create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Thiếu tên người dùng hoặc mật khẩu.'}), 400
        
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Tên người dùng đã tồn tại.'}), 409

    new_user = User(username=username, is_admin=False)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    create_activity_log('CREATE_USER', f'Admin tạo người dùng: {username}', target_user_id=new_user.id)
    return jsonify({'message': f'Người dùng {username} đã được tạo thành công.'}), 201


@app.route('/get_user_list', methods=['GET'])
@login_required
def get_user_list():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users]), 200

@app.route('/get_messages', methods=['GET'])
@login_required
def get_messages():
    target_user_id = request.args.get('target_user_id', type=int)
    
    if not target_user_id:
        return jsonify([]), 200
        
    # Lấy tin nhắn giữa người dùng hiện tại và người dùng mục tiêu
    messages = Message.query.filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.recipient_id == target_user_id),
            (Message.sender_id == target_user_id) & (Message.recipient_id == current_user.id)
        )
    ).order_by(Message.timestamp).all()
    
    # Đánh dấu tin nhắn nhận được là đã đọc
    unread_messages = Message.query.filter(
        (Message.sender_id == target_user_id) & 
        (Message.recipient_id == current_user.id) & 
        (Message.is_read == False)
    ).all()
    
    for msg in unread_messages:
        msg.is_read = True
    db.session.commit()
    
    return jsonify([msg.to_dict() for msg in messages]), 200

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'Không tìm thấy file.'}), 400
    
    file = request.files['file']
    recipient_id = request.form.get('recipient_id', type=int)

    if file.filename == '' or not recipient_id:
        return jsonify({'message': 'Tên file trống hoặc thiếu người nhận.'}), 400

    if not CLOUDINARY_CLOUD_NAME:
        return jsonify({'message': 'Lỗi server: Chưa cấu hình Cloudinary.'}), 500
        
    try:
        # Tải file lên Cloudinary
        upload_result = cloudinary.uploader.upload(
            file,
            folder="chat_files",
            resource_type="auto"
        )
        file_url = upload_result.get('secure_url')
        
        create_activity_log('UPLOAD_FILE', f'Đã tải file lên: {file.filename}', target_user_id=recipient_id)
        
        return jsonify({
            'message': 'Tải file thành công',
            'file_url': file_url
        }), 200
        
    except Exception as e:
        logger.error(f"Lỗi tải file lên Cloudinary: {e}")
        return jsonify({'message': f'Lỗi tải file lên server: {str(e)}'}), 500

# --- SOCKETIO EVENTS ---

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users[current_user.id] = request.sid
        logger.info(f"User connected: {current_user.username} (ID: {current_user.id}, SID: {request.sid})")
        # Thông báo cho người dùng khác user này đã online (TODO)
    else:
        # Ngắt kết nối nếu không được xác thực qua token (dù đã pass qua @login_required)
        # Logic này phụ thuộc vào cách client Flutter gửi token qua query params
        pass 

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        if online_users.get(current_user.id) == request.sid:
            del online_users[current_user.id]
            logger.info(f"User disconnected: {current_user.username} (ID: {current_user.id})")
            # Cập nhật trạng thái trong DB (sau 5s để tránh disconnect tạm thời)
            # Dùng eventlet.spawn_after để xử lý bất đồng bộ (tránh block SocketIO)
            eventlet.spawn_after(5, check_and_update_offline, current_user.id)
            # Thông báo user offline (TODO)
            
def check_and_update_offline(user_id):
    with app.app_context():
        # Chỉ cập nhật offline nếu user_id không có trong online_users
        if user_id not in online_users:
            user = User.query.get(user_id)
            if user:
                user.is_online = False
                db.session.commit()
                logger.info(f"User {user.username} marked as offline in DB.")

@socketio.on('send_message')
@login_required
def handle_send_message(data):
    recipient_id = data.get('recipient_id')
    content = data.get('content')
    
    if not recipient_id or not content:
        return
        
    # Lưu tin nhắn vào DB
    new_msg = Message(sender_id=current_user.id, recipient_id=recipient_id, content=content)
    db.session.add(new_msg)
    db.session.commit()
    
    recipient = User.query.get(recipient_id)
    if recipient:
        create_activity_log('SEND_MESSAGE', f'Gửi tin nhắn đến: {recipient.username}', target_user_id=recipient_id)
        
    # Chuẩn bị data gửi qua SocketIO
    msg_data = {
        'id': new_msg.id, 
        'sender': current_user.username, 
        'message': content, 
        'is_read': False,
        'timestamp': new_msg.timestamp.isoformat()
    }
    
    # Gửi đến người nhận (nếu online)
    recipient_sid = online_users.get(recipient_id)
    if recipient_sid:
        emit('message_from_server', msg_data, room=recipient_sid)
        
    # Gửi lại cho người gửi để cập nhật UI ngay lập tức
    emit('message_from_server', msg_data, room=request.sid)

@socketio.on('start_typing')
@login_required
def handle_start_typing(data):
    recipient_sid = online_users.get(data.get('recipient_id'))
    if recipient_sid:
        emit('user_is_typing', {'username': current_user.username}, room=recipient_sid)

@socketio.on('stop_typing')
@login_required
def handle_stop_typing(data):
    recipient_sid = online_users.get(data.get('recipient_id'))
    if recipient_sid:
        emit('user_stopped_typing', {'username': current_user.username}, room=recipient_sid)


if __name__ == '__main__':
    # Chạy server với eventlet
    # Đảm bảo bạn chạy lệnh: python server.py hoặc flask run (sau khi gọi init-db)
    print("Running Flask-SocketIO server with Eventlet...")
    socketio.run(app, host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)
