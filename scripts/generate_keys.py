from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_rsa_keypair(key_size: int = 4096):
    print(f"Generating {key_size}-bit RSA key pair... This may take a moment.")

    # 1. Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # 2. Save Private Key to student_private.pem
    # Encryption is set to NoEncryption() because this needs to be read by Docker automatically
    with open("student_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 3. Generate and Save Public Key to student_public.pem
    public_key = private_key.public_key()
    with open("student_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("SUCCESS: Keys generated!")
    print(f"Private Key: {os.path.abspath('student_private.pem')}")
    print(f"Public Key:  {os.path.abspath('student_public.pem')}")

if __name__ == "__main__":
    generate_rsa_keypair()