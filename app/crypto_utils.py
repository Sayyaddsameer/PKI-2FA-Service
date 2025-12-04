import base64
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP
    """
    print(f"DEBUG: Attempting to decrypt seed of length {len(encrypted_seed_b64)}")

    try:
        # 1. Base64 decode the encrypted seed string
        try:
            ciphertext = base64.b64decode(encrypted_seed_b64)
        except Exception as e:
            raise ValueError(f"Invalid Base64 input: {e}")

        # 2. RSA/OAEP decrypt with SHA-256
        # Critical Parameters:
        # - Padding: OAEP
        # - MGF: MGF1 with SHA-256
        # - Hash: SHA-256
        # - Label: None (default is None/empty bytes)
        decrypted_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 3. Decode bytes to UTF-8 string
        hex_seed = decrypted_bytes.decode('utf-8').strip()

        # 4. Validate: must be 64-character hex string
        # Check length
        if len(hex_seed) != 64:
            raise ValueError(f"Decrypted seed length is {len(hex_seed)}, expected 64.")

        # Check characters (0-9, a-f)
        if not re.fullmatch(r'^[0-9a-fA-F]+$', hex_seed):
            raise ValueError("Decrypted seed contains non-hex characters.")

        print("DEBUG: Decryption successful. Validating format... OK.")

        # 5. Return hex seed
        return hex_seed

    except ValueError as ve:
        # Re-raise validation errors directly
        raise ve
    except Exception as e:
        # Catch crypto errors (wrong key, wrong padding)
        raise ValueError(f"Decryption failed (Crypto Error): {e}")