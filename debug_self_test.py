from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from app.crypto_utils import decrypt_seed
import base64

def test_local_crypto():
    print("--- DEBUGGING LOCAL CRYPTO LOGIC ---")

    # 1. Load your PUBLIC key
    try:
        with open("student_public.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("❌ Error: student_public.pem not found.")
        return

    # 2. Encrypt a fake seed LOCALLY (Simulating the API)
    fake_seed_hex = "0" * 64 # 64 zeros
    print(f"Encrypting fake seed: {fake_seed_hex[:10]}...")

    ciphertext = public_key.encrypt(
        fake_seed_hex.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')

    # 3. Load your PRIVATE key
    try:
        with open("student_private.pem", "rb") as f:
            # We load the raw bytes to pass to your function if needed, 
            # but your function loads the file path usually.
            # Let's verify the file exists first.
            pass 
    except FileNotFoundError:
        print("❌ Error: student_private.pem not found.")
        return

    # 4. Try to Decrypt using your app's logic
    print("Attempting to decrypt using app.crypto_utils...")
    try:
        # We need to bypass the path loading in your util for this specific test
        # or load the key object manually if your util accepts objects.
        # Looking at your Step 5 code, decrypt_seed accepts (str, private_key_object) 
        # OR (str, path). Let's look at what we implemented in Step 5.

        # Re-loading private key object to match Step 5 signature:
        with open("student_private.pem", "rb") as key_file:
            private_key_obj = serialization.load_pem_private_key(key_file.read(), password=None)

        result = decrypt_seed(encrypted_b64, private_key_obj)

        if result == fake_seed_hex:
            print("\n✅ SUCCESS: Your crypto logic is PERFECT.")
            print("Conclusion: The problem is the API. It is sending you OLD data.")
        else:
            print("\n❌ FAILURE: Decryption worked but result was wrong.")

    except Exception as e:
        print(f"\n❌ CRITICAL FAILURE: Your code crashed: {e}")
        print("Conclusion: The problem is in app/crypto_utils.py")

if __name__ == "__main__":
    test_local_crypto()