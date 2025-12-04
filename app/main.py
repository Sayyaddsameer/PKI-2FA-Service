from fastapi import FastAPI, HTTPException, Response
import os
import sys

# Add the parent directory to sys.path so we can import 'app' modules correctly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models import DecryptRequest, VerifyRequest
from app.crypto_utils import decrypt_seed
from app.totp_utils import generate_totp_code, verify_totp_code

app = FastAPI()

# --- CONFIGURATION ---
# Detect if we are running in Docker or Local Windows
if os.path.exists("/data"):
    DATA_DIR = "/data"  # Docker environment
else:
    # Local Windows fallback
    DATA_DIR = os.path.join(os.getcwd(), "data_test")
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"⚠️  RUNNING LOCALLY: Using storage at {DATA_DIR}")

SEED_FILE_PATH = os.path.join(DATA_DIR, "seed.txt")
PRIVATE_KEY_PATH = "student_private.pem"

# --- ENDPOINT 1: DECRYPT SEED ---
@app.post("/decrypt-seed")
async def api_decrypt_seed(req: DecryptRequest):
    try:
        # 1. Load Private Key
        if not os.path.exists(PRIVATE_KEY_PATH):
            return Response(content='{"error": "Private key not found"}', media_type="application/json", status_code=500)

        # 2. Decrypt
        # We pass the path to the key file as expected by our utils
        hex_seed = decrypt_seed(req.encrypted_seed, PRIVATE_KEY_PATH)

        # 3. Save to storage
        with open(SEED_FILE_PATH, "w") as f:
            f.write(hex_seed)

        return {"status": "ok"}

    except Exception as e:
        # Return 500 on failure as requested
        print(f"Decryption Error: {e}")
        return Response(content='{"error": "Decryption failed"}', media_type="application/json", status_code=500)

# --- ENDPOINT 2: GENERATE 2FA ---
@app.get("/generate-2fa")
async def api_generate_2fa():
    # 1. Check if seed exists
    if not os.path.exists(SEED_FILE_PATH):
        return Response(content='{"error": "Seed not decrypted yet"}', media_type="application/json", status_code=500)

    try:
        # 2. Read seed
        with open(SEED_FILE_PATH, "r") as f:
            hex_seed = f.read().strip()

        # 3. Generate Code
        code, valid_for = generate_totp_code(hex_seed)
        return {"code": code, "valid_for": valid_for}

    except Exception as e:
        return Response(content=f'{{"error": "{str(e)}"}}', media_type="application/json", status_code=500)

# --- ENDPOINT 3: VERIFY 2FA ---
@app.post("/verify-2fa")
async def api_verify_2fa(req: VerifyRequest):
    # 1. Validate input
    if not req.code:
         return Response(content='{"error": "Missing code"}', media_type="application/json", status_code=400)

    # 2. Check if seed exists
    if not os.path.exists(SEED_FILE_PATH):
        return Response(content='{"error": "Seed not decrypted yet"}', media_type="application/json", status_code=500)

    try:
        # 3. Read seed
        with open(SEED_FILE_PATH, "r") as f:
            hex_seed = f.read().strip()

        # 4. Verify
        is_valid = verify_totp_code(hex_seed, req.code)
        return {"valid": is_valid}

    except Exception as e:
         return Response(content=f'{{"error": "{str(e)}"}}', media_type="application/json", status_code=500)