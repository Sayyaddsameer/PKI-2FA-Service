import os
import base64
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def generate_proof():
    print("--- GENERATING SUBMISSION PROOF ---")

    # 1. Get current commit hash
    try:
        # We use git to get the latest 40-char hash
        commit_hash = subprocess.check_output(['git', 'log', '-1', '--format=%H']).decode('utf-8').strip()
        print(f"✅ Commit Hash: {commit_hash}")
    except Exception as e:
        print("❌ Error getting git hash. Are you in the repo folder?")
        return

    # 2. Load Student Private Key
    try:
        with open("student_private.pem", "rb") as f:
            student_private_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print("❌ Error: student_private.pem not found.")
        return

    # 3. Sign the commit hash (RSA-PSS with SHA-256)
    # CRITICAL: We sign the ASCII bytes of the hash string, not the binary representation
    signature = student_private_key.sign(
        commit_hash.encode('utf-8'), 
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 4. Load Instructor Public Key
    try:
        with open("instructor_public.pem", "rb") as f:
            instructor_public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("❌ Error: instructor_public.pem not found. Did you download it?")
        return

    # 5. Encrypt Signature with Instructor Key (RSA/OAEP with SHA-256)
    encrypted_signature = instructor_public_key.encrypt(
        signature,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 6. Base64 Encode
    b64_proof = base64.b64encode(encrypted_signature).decode('utf-8')
    
    print("\n=== COPY THESE VALUES FOR SUBMISSION ===")
    print(f"\n1. Commit Hash:\n{commit_hash}")
    print(f"\n2. Encrypted Signature (One line!):\n{b64_proof}")

if __name__ == "__main__":
    generate_proof()