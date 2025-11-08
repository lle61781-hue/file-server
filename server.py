# server.py
# Flask server + SQLAlchemy + Cloudinary
# - Chỉnh các biến môi trường trước khi chạy / deploy:
#   - DATABASE_URL (ví dụ: postgresql://user:pass@host:5432/dbname) OR use SQLite file for local testing
#   - CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
# - Render/CI: đảm bảo biến môi trường DATABASE_URL & CLOUDINARY_* đã set

import os
import logging
from flask import Flask, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import cloudinary
import cloudinary.utils
from flask.cli import with_appcontext
import click

# --- Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Flask app init ---
app = Flask(__name__)

# --- Config: database ---
# Prefer DATABASE_URL env var (Render cung cấp DATABASE_URL for managed DBs typically)
db_url = os.getenv("DATABASE_URL") or os.getenv("SQLALCHEMY_DATABASE_URI") or "sqlite:///data.db"
# If using Heroku style DATABASE_URL with 'postgres://' adjust to 'postgresql://'
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- Cloudinary config ---
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)

# --- DB init ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # optional, if you want migrations

# --- Models ---
class File(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    # Đây là public_id của Cloudinary (string) — lưu khi upload lên Cloudinary
    public_id = db.Column(db.String(512), nullable=False, unique=True)
    # resource_type: 'raw' / 'image' / 'video' (tùy bạn lưu)
    resource_type = db.Column(db.String(50), nullable=True)
    # filename gợi ý (example: document.pdf)
    filename = db.Column(db.String(512), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "public_id": self.public_id,
            "resource_type": self.resource_type,
            "filename": self.filename
        }

# --- Helper: lấy file record từ DB
def get_file_record(file_id):
    """
    file_id có thể là integer id hoặc public_id string.
    Thử parse integer trước, nếu không thì tìm theo public_id.
    Trả File object hoặc None.
    """
    if not file_id:
        return None
    # nếu numeric => coi là id PK
    try:
        pk = int(file_id)
    except Exception:
        pk = None

    if pk:
        fr = File.query.get(pk)
        if fr:
            return fr
    # fallback: tìm theo public_id
    fr = File.query.filter_by(public_id=file_id).first()
    return fr

# --- Route: tạo download URL cho client ---
@app.route("/download/<string:file_id>", methods=["GET"])
def download_file_route(file_id):
    """
    Trả JSON: { "download_url": "<cloudinary-download-url>" }
    """
    file_record = get_file_record(file_id)
    if not file_record:
        logger.warning("File not found: %s", file_id)
        abort(404, description="File not found")

    # Tạo URL từ Cloudinary để trả file dưới dạng attachment/raw
    try:
        attachment_value = file_record.filename or True
        download_url, options = cloudinary.utils.cloudinary_url(
            file_record.public_id,
            resource_type='raw',         # ép raw để PDF/other raw types trả đúng
            secure=True,
            attachment=attachment_value, # hoặc attachment="mydoc.pdf" để gợi tên
            flags='download'             # tăng khả năng trả dạng download
        )
        logger.info("Generated download URL for %s -> %s", file_id, download_url)
    except Exception as e:
        logger.exception("Primary cloudinary_url generation failed, trying fallback.")
        try:
            download_url, options = cloudinary.utils.cloudinary_url(
                file_record.public_id,
                resource_type=(file_record.resource_type or 'raw'),
                secure=True,
                attachment=(file_record.filename or True)
            )
            logger.info("Fallback download URL for %s -> %s", file_id, download_url)
        except Exception:
            logger.exception("Fallback also failed for file %s", file_id)
            abort(500, description="Unable to generate download URL")

    return jsonify({"download_url": download_url})

# --- CLI command: init-db ---
# Đăng ký lệnh 'flask init-db' để tạo bảng ban đầu (hoặc seed minimal)
@app.cli.command("init-db")
@with_appcontext
def init_db_command():
    """
    Sử dụng: `flask init-db`
    Tạo tất cả table (db.create_all()) và có thể seed dữ liệu mẫu.
    """
    db.create_all()
    click.echo("Database tables created (db.create_all()).")
    # Tùy muốn: seed ví dụ 1 file (bỏ / chỉnh nếu không cần)
    test_public = os.getenv("INIT_SAMPLE_PUBLIC_ID")
    if test_public:
        # Nếu biến môi trường set, thêm sample File nếu chưa tồn tại
        existing = File.query.filter_by(public_id=test_public).first()
        if not existing:
            f = File(public_id=test_public, resource_type="raw", filename=os.getenv("INIT_SAMPLE_FILENAME", "sample.pdf"))
            db.session.add(f)
            db.session.commit()
            click.echo(f"Seeded sample File with public_id={test_public}")
    click.echo("init-db finished.")

# --- Optional: health check ---
@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"}), 200

# --- Run local dev ---
if __name__ == "__main__":
    # useful for local debug: flask run will import this module and CLI command registered
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
