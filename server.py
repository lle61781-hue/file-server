# server.py
# Flask server trả URL download an toàn cho file lưu trên Cloudinary.
# LƯU Ý: chỉnh cloudinary.config(...) theo cấu hình của bạn (BIẾN MÔI TRƯỜNG hoặc config file)
from flask import Flask, jsonify, abort, current_app
import logging
import cloudinary
import cloudinary.utils
import os

app = Flask(__name__)

# --- Cấu hình logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Cloudinary config: set từ biến môi trường hoặc thay bằng thông tin của bạn ---
# Ví dụ thiết lập (thường bạn đã set CLOUDINARY_URL hoặc tương tự trên Render)
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)

# --- HÀM lấy record file từ DB ---
# Thay phần này bằng truy vấn DB thực tế của bạn (SQLAlchemy / ORM / direct SQL).
# Trả về object có thuộc tính: public_id, resource_type (optional), filename (optional).
class FileRecord:
    def __init__(self, public_id, resource_type=None, filename=None):
        self.public_id = public_id
        self.resource_type = resource_type
        self.filename = filename

def get_file_record(file_id):
    """
    TODO: Thực hiện truy vấn DB thực tế tại đây và trả về FileRecord hoặc None.
    Ví dụ minh họa: giả sử public_id = file_id cho test.
    """
    # --- ví dụ giả (thay bằng DB lookup) ---
    # Nếu bạn lưu public_id khác, map file_id -> public_id tương ứng
    # Giả sử file_id là public_id:
    # return FileRecord(public_id=file_id, resource_type='raw', filename='document.pdf')
    #
    # Trả None nếu không tìm thấy
    return None


# --- Route trả URL download ---
@app.route("/download/<string:file_id>", methods=["GET"])
def download_file_route(file_id):
    """
    Trả JSON: { "download_url": "<cloudinary-download-url>" }
    Client sẽ dùng URL này để tải file nhị phân về.
    """
    # 1) lấy record từ DB
    file_record = get_file_record(file_id)
    if not file_record:
        logger.warning("File not found: %s", file_id)
        abort(404, description="File not found")

    # 2) Tạo cloudinary URL bắt buộc trả raw và attachment (gợi ý tên file)
    # - resource_type='raw' để chắc chắn Cloudinary trả nội dung thô (PDF, docx, v.v.)
    # - attachment = filename (string) để header Content-Disposition gợi ý tên file
    # - flags='download' để tăng khả năng trả file như download
    try:
        attachment_value = file_record.filename or True  # nếu có tên file thì dùng, ngược lại True
        download_url, options = cloudinary.utils.cloudinary_url(
            file_record.public_id,
            resource_type='raw',
            secure=True,
            attachment=attachment_value,
            flags='download'
        )
        logger.info("Generated download URL for %s -> %s", file_id, download_url)
    except Exception as e:
        # Fallback: nếu tạo không thành công, thử dùng resource_type từ DB (nếu có) hoặc raw
        logger.exception("Error generating Cloudinary download URL (primary). Trying fallback.")
        try:
            download_url, options = cloudinary.utils.cloudinary_url(
                file_record.public_id,
                resource_type=(file_record.resource_type or 'raw'),
                secure=True,
                attachment=(file_record.filename or True)
            )
            logger.info("Fallback download URL generated for %s -> %s", file_id, download_url)
        except Exception as e2:
            logger.exception("Fallback also failed. Cannot generate download URL for %s", file_id)
            abort(500, description="Unable to generate download URL")

    # 3) Trả URL cho client (client sẽ follow redirect / download)
    return jsonify({"download_url": download_url})


# --- Run server (local test) ---
if __name__ == "__main__":
    # PORT/host có thể thay khi deploy
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
