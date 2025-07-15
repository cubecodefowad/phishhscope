from flask import Flask, request, render_template, jsonify
from check_attachment import scan_file, VT_API_KEY
import os
import requests
from dotenv import load_dotenv
load_dotenv()
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from werkzeug.utils import secure_filename

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per hour"])
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Set up logging
logging.basicConfig(level=logging.INFO)

@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"[{request.remote_addr}] Rate limit exceeded.")
    return jsonify({"error": "Too many requests. Please wait and try again."}), 429

@app.errorhandler(400)
def bad_request_handler(e):
    return jsonify({"error": "Bad request."}), 400

@app.errorhandler(500)
def internal_error_handler(e):
    return jsonify({"error": "An internal error occurred. Please try again later."}), 500

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    return render_template('function.html')

@app.route('/scan-attachment', methods=['POST'])
@limiter.limit("10 per minute")
def scan_attachment():
    try:
        if 'file' not in request.files:
            logging.info(f"[{request.remote_addr}] No file uploaded.")
            return jsonify({"error": "No file uploaded"}), 400
        file = request.files['file']
        # File type and size validation
        allowed_mimetypes = [
            'application/pdf', 'image/png', 'image/jpeg', 'image/gif',
            'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/zip', 'text/plain', 'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        ]
        max_size = 10 * 1024 * 1024  # 10MB
        if file.mimetype not in allowed_mimetypes:
            logging.info(f"[{request.remote_addr}] Rejected file type: {file.mimetype} ({file.filename})")
            return jsonify({"error": "File type not allowed. Allowed types: PDF, images, Office docs, text, zip."}), 400
        file.seek(0, 2)  # Seek to end
        size = file.tell()
        file.seek(0)
        if size > max_size:
            logging.info(f"[{request.remote_addr}] Rejected file size: {size} bytes ({file.filename})")
            return jsonify({"error": "File too large. Max size is 10MB."}), 400
        # Use in-memory file, do not save to disk
        safe_filename = secure_filename(file.filename)
        logging.info(f"[{request.remote_addr}] Scanning file: {safe_filename} ({size} bytes, {file.mimetype})")
        result = scan_file(file.stream, safe_filename)
        return jsonify(result)
    except Exception as ex:
        logging.exception("Unexpected error in scan_attachment")
        return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500

@app.route('/check-status/<analysis_id>', methods=['GET'])
def check_status(analysis_id):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        status = data["data"]["attributes"]["status"]
        if status == "completed":
            stats = data["data"]["attributes"]["stats"]
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            return jsonify({
                "done": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "explanation": f"This file was flagged by {malicious + suspicious} security engines."
            })
        return jsonify({"done": False})
    else:
        return jsonify({"error": "Failed to check status"}), 500

if __name__ == '__main__':
    app.run(debug=True)
