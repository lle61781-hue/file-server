import eventlet
eventlet.monkey_patch()

import os, click
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask.cli import with_appcontext 
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, not_
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps
from flask_socketio import SocketIO, emit
import uuid
import logging
import requests
import urllib.parse 
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024 
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')

# Tạo thư mục uploads nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet') 

online_users = {}

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({'message': 'Yêu cầu quyền Admin!'}), 403
        return f(*args, **kwargs)
    return decorated_function

def create_activity_log(action, details=None, target_user_id=None):
    try:
        with app.app_context():
            user_id = current_user.id if current_user.is_authenticated else None
            
            log_entry = ActivityLog(
                user_id=user_id,
                action=action,
                details=details,
                target_user_id=target_user_id
            )
            db.session.add(log_entry)
            db.session.commit()
    except Exception as e:
        logger.error(f"Error creating activity log: {e}")
        db.session.rollback()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    avatar_url = db.Column(db.String(256), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password) 

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_opened_by = db.Column(db.String(80), nullable=True) 
    last_opened_at = db.Column(db.DateTime, nullable=True) 
    folder = db.Column(db.String(100), default='Gốc')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def initialize_database(app, db):
    with app.app_context(): 
        try:
            db.create_all() 
            logger.info("Database tables created successfully.")
            
            # Tạo admin user mặc định nếu chưa có
            if User.query.first() is None:
                admin_user = User(username='admin', is_admin=True)
                admin_user.set_password('adminpass')
                db.session.add(admin_user)
                db.session.commit()
                logger.info("Default admin user created.")
                
        except Exception as e:
            logger.error(f"Error initializing database: {e}")

@app.route('/')
def index():
    return "Server is running!"

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username, password = data.get('username'), data.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            create_activity_log('LOGIN')
            return jsonify({
                'message': 'Đăng nhập thành công!', 
                'user_id': user.id, 
                'username': user.username, 
                'is_admin': user.is_admin, 
                'avatar_url': user.avatar_url
            })
        return jsonify({'message': 'Sai tên đăng nhập hoặc mật khẩu!'}), 401
    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({'message': 'Lỗi server!'}), 500

@app.route('/online-users', methods=['GET'])
@login_required
def get_online_users():
    try:
        online_user_ids = list(online_users.keys())
        users = User.query.filter(User.id.in_(online_user_ids)).all()
        users_info = []
        for u in users:
            if u.id != current_user.id:
                users_info.append({
                    'id': u.id, 
                    'username': u.username, 
                    'avatar_url': u.avatar_url
                })
        return jsonify({'users': users_info})
    except Exception as e:
        logger.error(f"Error getting online users: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/all-users', methods=['GET'])
@login_required 
def get_all_users():
    try:
        users = User.query.all()
        users_info = []
        for u in users:
            if u.id != current_user.id:
                users_info.append({
                    'id': u.id, 
                    'username': u.username, 
                    'avatar_url': u.avatar_url,
                    'is_online': u.id in online_users
                })
        return jsonify({'users': users_info})
    except Exception as e:
        logger.error(f"Error getting all users: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'Không tìm thấy file.'}), 400
    
    target_folder = request.form.get('target_folder', 'Gốc')
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'message': 'Tên file không hợp lệ.'}), 400
        
    try:
        # Tạo tên file an toàn
        original_filename = secure_filename(file.filename)
        file_extension = os.path.splitext(original_filename)[1]
        unique_filename = f"{uuid.uuid4().hex}{file_extension}"
        
        # Tạo thư mục con cho folder nếu cần
        if target_folder != 'Gốc':
            folder_path = os.path.join(app.config['UPLOAD_FOLDER'], target_folder)
            os.makedirs(folder_path, exist_ok=True)
            file_path = os.path.join(folder_path, unique_filename)
        else:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Lưu file
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        
        # Lưu thông tin file vào database
        new_file = File(
            filename=original_filename,
            file_path=file_path,
            file_size=file_size,
            user_id=current_user.id,
            folder=target_folder
        )
        db.session.add(new_file)
        db.session.commit()
        
        create_activity_log('UPLOAD_FILE', f'File: {original_filename}')
        
        return jsonify({'message': f'File {original_filename} đã được tải lên thành công!'})
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'message': f'Lỗi khi tải file lên: {e}'}), 500

@app.route('/download/<int:file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    try:
        file_record = File.query.get_or_404(file_id)
        
        # Kiểm tra quyền truy cập
        if not current_user.is_admin and file_record.user_id != current_user.id:
            return jsonify({'message': 'Bạn không có quyền truy cập file này!'}), 403
        
        create_activity_log('DOWNLOAD_FILE', f'File: {file_record.filename}')
        
        return send_file(file_record.file_path, as_attachment=True, download_name=file_record.filename)
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({'message': 'Lỗi khi tải file!'}), 500

@app.route('/files', methods=['GET'])
@login_required
def get_files():
    try:
        search_term = request.args.get('search', '').strip()
        folder = request.args.get('folder', 'Gốc')
        
        # Base query
        files_query = File.query
        
        # Lọc theo folder
        if folder != 'Gốc':
            files_query = files_query.filter(File.folder == folder)
        else:
            files_query = files_query.filter(File.folder == 'Gốc')
        
        # Lọc theo search term
        if search_term:
            files_query = files_query.filter(File.filename.ilike(f'%{search_term}%'))
        
        files = files_query.all()
        
        file_list = []
        for f in files:
            uploaded_by = User.query.get(f.user_id)
            file_list.append({
                'id': f.id,
                'filename': f.filename,
                'uploaded_by': uploaded_by.username if uploaded_by else 'Unknown',
                'file_size': f.file_size,
                'upload_date': f.upload_date.isoformat(),
                'last_opened_by': f.last_opened_by,
                'last_opened_at': f.last_opened_at.isoformat() if f.last_opened_at else None,
                'folder': f.folder
            })
            
        return jsonify({'files': file_list})
        
    except Exception as e:
        logger.error(f"Error getting files: {e}")
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/file/opened/<int:file_id>', methods=['POST'])
@login_required
def file_opened(file_id):
    try:
        file_record = File.query.get_or_404(file_id)
        
        # Cập nhật thông tin mở file
        file_record.last_opened_by = current_user.username
        file_record.last_opened_at = datetime.now(timezone.utc)
        
        db.session.commit()
        
        create_activity_log('OPEN_FILE', f'File: {file_record.filename}')
        
        return jsonify({'message': 'Đã ghi nhận mở file.'})
        
    except Exception as e:
        logger.error(f"Error recording file open: {e}")
        return jsonify({'message': 'Lỗi khi ghi nhận!'}), 500

@app.route('/delete-file/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    try:
        file_record = File.query.get_or_404(file_id)
        
        # Chỉ admin hoặc người upload mới được xóa
        if not current_user.is_admin and file_record.user_id != current_user.id:
            return jsonify({'message': 'Bạn không có quyền xóa file này!'}), 403
        
        # Xóa file vật lý
        if os.path.exists(file_record.file_path):
            os.remove(file_record.file_path)
        
        # Xóa record trong database
        db.session.delete(file_record)
        db.session.commit()
        
        create_activity_log('DELETE_FILE', f'File: {file_record.filename}')
        
        return jsonify({'message': 'Đã xóa file thành công!'})
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'message': 'Lỗi khi xóa file!'}), 500

@app.route('/admin/folders', methods=['GET'])
@login_required
def get_folders():
    try:
        # Lấy danh sách thư mục từ database
        folders = db.session.query(File.folder).distinct().all()
        folder_list = ['Gốc'] + [f[0] for f in folders if f[0] != 'Gốc']
        
        return jsonify({'folders': folder_list})
        
    except Exception as e:
        logger.error(f"Error getting folders: {e}")
        return jsonify({'folders': ['Gốc']})

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users[current_user.id] = request.sid
        logger.info(f"User {current_user.username} connected. Online: {list(online_users.keys())}")
        emit('user_connected', {
            'id': current_user.id, 
            'username': current_user.username
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        online_users.pop(current_user.id, None)
        logger.info(f"User {current_user.username} disconnected. Online: {list(online_users.keys())}")
        emit('user_disconnected', {
            'id': current_user.id, 
            'username': current_user.username
        }, broadcast=True)

@socketio.on('private_message')
@login_required
def handle_private_message(data):
    recipient_id = data.get('recipient_id')
    content = data.get('message')
    
    if not recipient_id or not content:
        return
        
    # Lưu tin nhắn vào database
    new_msg = Message(
        sender_id=current_user.id, 
        recipient_id=recipient_id, 
        content=content
    )
    db.session.add(new_msg)
    db.session.commit()
    
    # Gửi tin nhắn đến recipient nếu online
    recipient_sid = online_users.get(recipient_id)
    if recipient_sid:
        emit('message_from_server', {
            'id': new_msg.id,
            'sender': current_user.username,
            'message': content,
            'is_read': False
        }, room=recipient_sid)
    
    # Gửi tin nhắn lại cho sender để xác nhận
    emit('message_from_server', {
        'id': new_msg.id,
        'sender': current_user.username,
        'message': content,
        'is_read': False
    }, room=request.sid)

if __name__ == '__main__':
    initialize_database(app, db)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
