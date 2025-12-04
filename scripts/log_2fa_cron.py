#!/usr/bin/env python3
import sys
import os
import datetime
# Add /app to python path to import modules
sys.path.append('/app')

# We need to import the TOTP logic from the app package
# Since this script runs as standalone, we need to handle imports carefully
try:
    from app.totp_utils import generate_totp_code
except ImportError:
    # Fallback if running from root
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from app.totp_utils import generate_totp_code

SEED_FILE = "/data/seed.txt"

def main():
    if not os.path.exists(SEED_FILE):
        print(f"Seed file not found at {SEED_FILE}", file=sys.stderr)
        return

    try:
        with open(SEED_FILE, "r") as f:
            hex_seed = f.read().strip()

        # Generate code using the shared logic
        code, _ = generate_totp_code(hex_seed)

        # Use UTC timestamp
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        # Print to stdout (which cron redirects to file)
        print(f"{timestamp} - 2FA Code: {code}")

    except Exception as e:
        print(f"Error generating cron 2FA: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()