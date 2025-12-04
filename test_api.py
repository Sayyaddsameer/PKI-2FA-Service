import requests
import os

# Load the encrypted seed string we saved in Step 4
if not os.path.exists("encrypted_seed.txt"):
    print("❌ Error: encrypted_seed.txt missing. Run Step 4 first.")
    exit()

with open("encrypted_seed.txt", "r") as f:
    encrypted_seed = f.read().strip()

BASE_URL = "http://127.0.0.1:8080"

print("--- 1. Testing Decryption ---")
resp = requests.post(f"{BASE_URL}/decrypt-seed", json={"encrypted_seed": encrypted_seed})
print(f"Status: {resp.status_code}")
print(f"Response: {resp.json()}")

print("\n--- 2. Testing Generation ---")
resp = requests.get(f"{BASE_URL}/generate-2fa")
data = resp.json()
print(f"Response: {data}")
code = data.get('code')

if code:
    print(f"\n--- 3. Testing Verification (Valid Code: {code}) ---")
    resp = requests.post(f"{BASE_URL}/verify-2fa", json={"code": code})
    print(f"Response: {resp.json()}")

print(f"\n--- 4. Testing Verification (Invalid Code) ---")
resp = requests.post(f"{BASE_URL}/verify-2fa", json={"code": "000000"})
print(f"Response: {resp.json()}")