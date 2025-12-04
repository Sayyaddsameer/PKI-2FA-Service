import requests
import json
import os


STUDENT_ID = "23P31A0552"

GITHUB_REPO_URL = "https://github.com/Sayyaddsameer/PKI-2FA-Service" 

# ==========================================

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

def request_seed():
    print(f"Reading public key from: {os.path.abspath('student_public.pem')}")

    # 1. Read the public key
    try:
        with open("student_public.pem", "r") as f:
            public_key_content = f.read()
    except FileNotFoundError:
        print("ERROR: student_public.pem not found! Did you run Step 2?")
        return

    # 2. Prepare the payload
    # Note: The JSON library handles the newline (\n) formatting automatically
    payload = {
        "student_id": STUDENT_ID,
        "github_repo_url": GITHUB_REPO_URL,
        "public_key": public_key_content
    }

    print(f"Connecting to Instructor API...")
    print(f"Sending request for Student ID: {STUDENT_ID}")
    print(f"Linked to Repo: {GITHUB_REPO_URL}")

    try:
        # 3. Send POST request
        response = requests.post(API_URL, json=payload, timeout=15)

        # Check for HTTP errors (400, 500, etc)
        if response.status_code != 200:
            print(f"\n❌ API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return

        # 4. Parse Response
        data = response.json()

        if "encrypted_seed" in data:
            # 5. Save the encrypted seed
            with open("encrypted_seed.txt", "w") as f:
                f.write(data["encrypted_seed"])
            print("\n✅ SUCCESS! Encrypted seed saved to 'encrypted_seed.txt'")
            print("⚠️  REMINDER: Do NOT commit encrypted_seed.txt to GitHub.")
        else:
            print(f"\n❌ Error: Response did not contain 'encrypted_seed'.")
            print(f"Full Response: {data}")

    except Exception as e:
        print(f"\n❌ Connection Failed: {e}")

if __name__ == "__main__":
    request_seed()