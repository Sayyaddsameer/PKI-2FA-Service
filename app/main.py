from fastapi import FastAPI, HTTPException, Response
from cryptography.hazmat.primitives import serialization  # <--- NEW IMPORT
import os
import sys

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models import DecryptRequest, VerifyRequest
from app.crypto_utils import decrypt_seed
from app.totp_utils import generate_totp_code, verify_totp_code

app = FastAPI()

# --- CONFIGURATION ---
if os.path.exists("/data"):
    DATA_DIR = "/data"
else:
    DATA_DIR = os.path.join(os.getcwd(), "data_test")
    os.makedirs(DATA_DIR, exist_ok=True)
    # Fixed syntax error from before
    print(f"⚠️  RUNNING LOCALLY: Using storage at {DATA_DIR}")

SEED_FILE_PATH = os.path.join(DATA_DIR, "seed.txt")
PRIVATE_KEY_PATH = "student_private.pem"

# --- ENDPOINT 1: DECRYPT SEED ---
@app.post("/decrypt-seed")
async def api_decrypt_seed(req: DecryptRequest):
    try:
        # 1. Check if Private Key file exists
        if not os.path.exists(PRIVATE_KEY_PATH):
            return Response(content='{"error": "Private key not found"}', media_type="application/json", status_code=500)

        # 2. LOAD the Private Key (This was missing!)
        with open(PRIVATE_KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        # 3. Decrypt (Now passing the Key Object, not the string path)
        hex_seed = decrypt_seed(req.encrypted_seed, private_key)
        
        # 4. Save to storage
        with open(SEED_FILE_PATH, "w") as f:
            f.write(hex_seed)
            
        return {"status": "ok"}
        
    except Exception as e:
        print(f"Decryption Error: {e}")
        return Response(content='{"error": "Decryption failed"}', media_type="application/json", status_code=500)

# --- ENDPOINT 2: GENERATE 2FA ---
@app.get("/generate-2fa")
async def api_generate_2fa():
    if not os.path.exists(SEED_FILE_PATH):
        return Response(content='{"error": "Seed not decrypted yet"}', media_type="application/json", status_code=500)
    
    try:
        with open(SEED_FILE_PATH, "r") as f:
            hex_seed = f.read().strip()
        
        code, valid_for = generate_totp_code(hex_seed)
        return {"code": code, "valid_for": valid_for}
        
    except Exception as e:
        return Response(content=f'{{"error": "{str(e)}"}}', media_type="application/json", status_code=500)

# --- ENDPOINT 3: VERIFY 2FA ---
@app.post("/verify-2fa")
async def api_verify_2fa(req: VerifyRequest):
    if not req.code:
            return Response(content='{"error": "Missing code"}', media_type="application/json", status_code=400)

    if not os.path.exists(SEED_FILE_PATH):
        return Response(content='{"error": "Seed not decrypted yet"}', media_type="application/json", status_code=500)

    try:
        with open(SEED_FILE_PATH, "r") as f:
            hex_seed = f.read().strip()
            
        is_valid = verify_totp_code(hex_seed, req.code)
        return {"valid": is_valid}
        
    except Exception as e:
            return Response(content=f'{{"error": "{str(e)}"}}', media_type="application/json", status_code=500)