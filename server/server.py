# server.py (FINAL CORRECTED VERSION)
from flask import Flask, request, jsonify, send_from_directory
import jwt, time, os, pyotp, geoip2.database, logging, json, base64
from werkzeug.utils import secure_filename
from logging.handlers import RotatingFileHandler
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# --- Logging Setup ---
security_logger = logging.getLogger('SecurityLogger')
if not security_logger.handlers:
    security_logger.setLevel(logging.INFO)
    handler = RotatingFileHandler('security_events.log', maxBytes=10000, backupCount=5)
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            return json.dumps({"timestamp": self.formatTime(record, self.datefmt), "level": record.levelname, "event": record.getMessage(), "details": record.args})
    formatter = JsonFormatter()
    handler.setFormatter(formatter)
    security_logger.addHandler(handler)

# --- Config ---
SECRET, JWT_ALGO, JWT_EXP_SECONDS = "your-secret", "HS256", 300
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
GEOIP_DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'GeoLite2-Country.mmdb')

# --- USERS DICTIONARY with Device Public Key ---
USERS = {
    "G7": {
        "password": "welcomepanel7",
        "mfa_secret": "N5QTANAEWFY4NURI2BCNJ6DZVRBXYPFL",
        "allowed_country": "IN",
        "device_public_key": """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyV14TZJgk+yfwFcy/paV
kzAPapxxkR9CVFas8rosnS77WKntUM06Vj4UbmRE1Q5Op0XM7mPvskSDg8CxzwQZ
ZPrtoZfuYUUFfGlLHKhRIwVsYT3u9Qo6uV//0V3WQPWhGn5uLPzN3z38e9LX7HHV
VmdyK7+HM7ExBDhEdF6d/GtnDfO0eQggj2/wibJG7rdlqMqGVajWNC9GrzR/PdIB
c2+1tr9jWdakhDXUvK7FR9Vq0KP5AC7ZFvnv4XUR5XDyXC1EuKHxbc+V+3z2dcar
kd2NlFvLGV7qxfjTB1xibWTgaPJlAINAQNNipDzApBDtBoXz+e89hYD9Oj2j9IAX
cwIDAQAB
-----END PUBLIC KEY-----"""
    }
}

# --- Flask App ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
CHALLENGES = {}

try:
    geoip_reader = geoip2.database.Reader(GEOIP_DATABASE)
except FileNotFoundError: geoip_reader = None

# --- JWT & Crypto Helpers ---
def issue_jwt(username):
    payload = {"sub": username, "iat": int(time.time()), "exp": int(time.time()) + JWT_EXP_SECONDS}
    return jwt.encode(payload, SECRET, algorithm=JWT_ALGO)
def verify_jwt(token):
    try: return jwt.decode(token, SECRET, algorithms=[JWT_ALGO])
    except: return None

# --- Routes ---
@app.route("/auth/start", methods=["POST"])
def auth_start():
    data = request.json or {}
    username, password, mfa_code = data.get("username"), data.get("password"), data.get("mfa_code")
    user, ip_address = USERS.get(username), request.remote_addr
    
    # Check 1: Credentials
    if not user or user["password"] != password: return jsonify({"error": "invalid credentials"}), 403
    # Check 2: MFA
    if not pyotp.TOTP(user["mfa_secret"]).verify(mfa_code): return jsonify({"error": "invalid MFA code"}), 403
    
    # Check 3: Location (This was the missing part)
    if geoip_reader:
        country_code = 'IN' if ip_address == '127.0.0.1' else 'unknown'
        if ip_address != '127.0.0.1':
            try: country_code = geoip_reader.country(ip_address).country.iso_code
            except: pass
        if country_code != user["allowed_country"]:
            security_logger.warning("login_failure", {"username": username, "ip": ip_address, "reason": "location_denied", "attempted": country_code, "allowed": user["allowed_country"]})
            return jsonify({"error": "access denied from your location"}), 403
            
    # If all checks pass, issue the device challenge
    challenge = os.urandom(32).hex()
    CHALLENGES[username] = challenge
    security_logger.info("auth_challenge_issued", {"username": username, "ip": ip_address})
    return jsonify({"challenge": challenge})

@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    data = request.json or {}
    username, signature_b64 = data.get("username"), data.get("signature")
    user, ip_address = USERS.get(username), request.remote_addr

    challenge = CHALLENGES.pop(username, None)
    if not challenge or not signature_b64:
        return jsonify({"error": "invalid challenge"}), 403
        
    try:
        public_key = serialization.load_pem_public_key(user["device_public_key"].encode())
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, challenge.encode(), padding.PKCS1v15(), hashes.SHA256())
        
        security_logger.info("device_verified_and_login_success", {"username": username, "ip": ip_address})
        return jsonify({"access_token": issue_jwt(username), "expires_in": JWT_EXP_SECONDS})
    except Exception:
        security_logger.warning("device_verify_failure", {"username": username, "ip": ip_address, "reason": "signature_invalid"})
        return jsonify({"error": "device signature verification failed"}), 403

# (Upload, Download, Files routes are unchanged)
@app.route("/upload", methods=["POST"])
def upload():
    token = request.headers.get("Authorization", "").split(" ")[-1]
    user = verify_jwt(token)
    if not user: return jsonify({"error": "invalid or expired token"}), 403
    file = request.files.get("file")
    if not file: return jsonify({"error": "no file provided"}), 400
    username, filename = user["sub"], secure_filename(file.filename)
    user_upload_path = os.path.join(app.config['UPLOAD_FOLDER'], username)
    os.makedirs(user_upload_path, exist_ok=True)
    file.save(os.path.join(user_upload_path, filename))
    security_logger.info("file_upload", {"username": username, "filename": filename, "ip": request.remote_addr})
    return jsonify({"message": f"{filename} uploaded successfully"})
@app.route("/files", methods=["GET"])
def list_files_route():
    token = request.headers.get("Authorization", "").split(" ")[-1]
    user = verify_jwt(token)
    if not user: return jsonify({"error": "invalid or expired token"}), 403
    user_upload_path = os.path.join(app.config['UPLOAD_FOLDER'], user["sub"])
    if not os.path.isdir(user_upload_path): return jsonify([])
    return jsonify([{"filename": f} for f in os.listdir(user_upload_path)])
@app.route("/download/<filename>", methods=["GET"])
def download(filename):
    token = request.headers.get("Authorization", "").split(" ")[-1]
    user = verify_jwt(token)
    if not user: return jsonify({"error": "invalid or expired token"}), 403
    username = user["sub"]
    user_upload_path = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if not os.path.exists(os.path.join(user_upload_path, filename)): return jsonify({"error": "file not found"}), 404
    security_logger.info("file_download", {"username": username, "filename": filename, "ip": request.remote_addr})
    return send_from_directory(user_upload_path, filename, as_attachment=True)

if __name__ == "__main__":
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(port=5000, debug=False)