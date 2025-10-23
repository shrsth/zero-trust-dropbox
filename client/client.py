# client.py (FINAL VERSION with Device Identity)
import requests, os, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

SERVER_URL, SALT = "http://127.0.0.1:5000", b'your-static-salt-for-demo'

def authenticate(username, password, mfa_code):
    """Performs the full multi-step authentication flow including device verification."""
    # Step 1: Initial authentication to get a challenge
    initial_data = {"username": username, "password": password, "mfa_code": mfa_code}
    try:
        resp_start = requests.post(f"{SERVER_URL}/auth/start", json=initial_data)
        if resp_start.status_code != 200:
            return resp_start.json()
        challenge = resp_start.json().get("challenge")
    except requests.exceptions.RequestException:
        return {"error": "Connection to server failed."}

    # Step 2: Sign the challenge with the device's private key
    try:
        with open("device_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        signature = private_key.sign(
            challenge.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode()
    except FileNotFoundError:
        return {"error": "Device key not found. Please register this device."}
    except Exception:
        return {"error": "Failed to sign device challenge."}

    # Step 3: Send the signature to the server to get the final session token
    verify_data = {"username": username, "signature": signature_b64}
    try:
        resp_verify = requests.post(f"{SERVER_URL}/auth/verify", json=verify_data)
        return resp_verify.json()
    except requests.exceptions.RequestException:
        return {"error": "Connection to server failed during verification."}

# (Upload, Download, List files functions remain the same)
def list_files(token):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{SERVER_URL}/files", headers=headers)
    return [f["filename"] for f in resp.json()] if resp.status_code == 200 else []
def upload_file(token, filepath, password):
    headers = {"Authorization": f"Bearer {token}"}
    key = derive_key(password, SALT)
    with open(filepath, "rb") as f: encrypted_data = Fernet(key).encrypt(f.read())
    files = {"file": (os.path.basename(filepath), encrypted_data)}
    resp = requests.post(f"{SERVER_URL}/upload", headers=headers, files=files)
    return resp.status_code == 200
def download_file(token, filename, save_as, password):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{SERVER_URL}/download/{filename}", headers=headers, stream=True)
    if resp.status_code != 200:
        try: return False, resp.json().get("error", "Unknown download error")
        except: return False, f"Server returned status {resp.status_code}"
    try:
        key = derive_key(password, SALT)
        decrypted_data = Fernet(key).decrypt(resp.content)
        with open(save_as, "wb") as f: f.write(decrypted_data)
        return True, None
    except Exception:
        return False, "Decryption failed. Wrong password or corrupt file."