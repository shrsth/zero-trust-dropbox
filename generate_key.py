# generate_key.py
import pyotp
secret_key = pyotp.random_base32()
print(f"Your secret key is: {secret_key}")