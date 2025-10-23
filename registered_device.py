# register_device.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate a new private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Save the private key to a file (keep this secret!)
with open("device_private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Get the public key
public_key = private_key.public_key()

# Save the public key to a file (this part is shared with the server)
with open("device_public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("✅ Device key pair generated successfully!")
print("-> device_private_key.pem (KEEP THIS SECRET ON YOUR CLIENT)")
print("-> device_public_key.pem (COPY THE CONTENT OF THIS FILE TO THE SERVER)")