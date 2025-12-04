import pyotp
import base64
import time
import binascii

def get_totp_object(hex_seed: str):
    """
    Helper function to create the TOTP object from a hex seed.
    Standardizes the conversion logic to avoid repetition.
    """
    try:
        # 1. Convert hex seed to bytes
        # "aabbcc" -> b'\xaa\xbb\xcc'
        seed_bytes = bytes.fromhex(hex_seed)

        # 2. Convert bytes to base32 encoding
        # TOTP libraries require Base32 secrets (like "JBSWY3DPEHPK3PXP")
        base32_bytes = base64.b32encode(seed_bytes)

        # Decode to string for pyotp
        base32_seed = base32_bytes.decode('utf-8')

        # 3. Create TOTP object
        # Defaults: SHA-1, 30s period, 6 digits
        return pyotp.TOTP(base32_seed, digits=6, interval=30)

    except Exception as e:
        raise ValueError(f"Failed to process seed: {e}")

def generate_totp_code(hex_seed: str):
    """
    Generate current TOTP code from hex seed
    Returns: (code, valid_for_seconds)
    """
    totp = get_totp_object(hex_seed)

    # 4. Generate current TOTP code
    code = totp.now()

    # Calculate remaining validity seconds
    # time.time() % 30 gives seconds elapsed in current window
    # 30 - elapsed gives remaining seconds
    time_remaining = int(totp.interval - (time.time() % totp.interval))

    return code, time_remaining

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance
    valid_window=1 means accept current code, previous code (-30s), and next code (+30s)
    """
    try:
        totp = get_totp_object(hex_seed)

        # Verify code with time window tolerance
        # This handles clock skew between your server and the user/evaluator
        return totp.verify(code, valid_window=valid_window)

    except Exception:
        return False