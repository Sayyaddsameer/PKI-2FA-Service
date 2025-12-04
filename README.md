# PKI & TOTP Two-Factor Authentication Service

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.95+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Container-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Security](https://img.shields.io/badge/RSA-4096-red?style=for-the-badge)

## Project Overview

This project implements a secure, containerized microservice that demonstrates enterprise-grade security practices. It combines **Public Key Infrastructure (PKI)** for secure seed transmission and **Time-based One-Time Password (TOTP)** for user authentication.

The service is built with **FastAPI**, containerized with **Docker**, and includes an automated **Cron** job for background auditing.

### Key Features
* **Asymmetric Encryption:** Uses RSA 4096-bit encryption (OAEP padding) to securely receive TOTP seeds.
* **2FA Implementation:** Generates and verifies standard 6-digit TOTP codes (SHA-1, 30s period).
* **Persistence:** Docker volumes ensure seed data and logs survive container restarts.
* **Automated Logging:** A background cron job generates and logs valid 2FA codes every minute.
* **Security:** Implements input validation via Pydantic models and strict error handling.

---

## Technology Stack

* **Language:** Python 3.11
* **Framework:** FastAPI + Uvicorn
* **Containerization:** Docker & Docker Compose
* **Cryptography:** `cryptography` library (RSA-PSS, RSA-OAEP)
* **TOTP:** `pyotp` library
* **Task Scheduling:** Linux Cron

---

## Project Structure

PKI-2FA-Service/
├── app/
│   ├── main.py              # FastAPI application entry point
│   ├── models.py            # Pydantic data models
│   ├── crypto_utils.py      # RSA decryption logic
│   └── totp_utils.py        # TOTP generation & verification logic
├── cron/
│   └── 2fa-cron             # Cron job definition (LF line endings)
├── scripts/
│   ├── generate_keys.py     # Setup: Generates RSA keypair
│   ├── request_seed.py      # Setup: Requests encrypted seed from API
│   ├── log_2fa_cron.py      # Runtime: Script executed by cron
│   └── generate_proof.py    # Submission: Generates signed commit proof
├── Dockerfile               # Multi-stage Docker build
├── docker-compose.yml       # Service orchestration and volumes
├── requirements.txt         # Python dependencies
└── README.md                # Project documentation

## Getting Started

### Prerequisites
* Docker & Docker Compose installed on your machine.
* Git.

### Installation & Run

1.  **Clone the repository:**
    
    git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git)
    cd YOUR_REPO_NAME
    

2.  **Build and Start the Container:**
   
    docker-compose up -d --build
    *This will start the API server on port `8080` and the Cron daemon in the background.*

4.  **Verify the container is running:**
   
    docker ps

---

## API Documentation

The microservice exposes the following REST endpoints on port **8080**.

### 1. Decrypt Seed
Receives the encrypted seed (provided by the instructor API), decrypts it using the private key, and stores it persistently.

* **Endpoint:** `POST /decrypt-seed`
* **Content-Type:** `application/json`
* **Payload:**
    
    {
      "encrypted_seed": "BASE64_ENCODED_STRING..."
    }
* **Response (200 OK):**
    
    {
      "status": "ok"
    }

### 2. Generate 2FA Code
Generates a current TOTP code based on the stored seed.

* **Endpoint:** `GET /generate-2fa`
* **Response (200 OK):**
    
    {
      "code": "123456",
      "valid_for": 28
    }

### 3. Verify 2FA Code
Verifies a user-provided code against the stored seed. Supports a tolerance of ±1 period (30 seconds).

* **Endpoint:** `POST /verify-2fa`
* **Payload:**
  
    {
      "code": "123456"
    }
    
* **Response (200 OK):**
    
    {
      "valid": true
    }
    *(Or `false` if invalid)*

---

## Cron Job & Persistence

### Automated Logging
A Cron job is configured to run every minute inside the container. It performs the following:
1.  Reads the decrypted seed from `/data/seed.txt`.
2.  Generates the current 2FA code.
3.  Logs the timestamp (UTC) and code to `/cron/last_code.txt`.

### Verifying Cron Output
To check the automated logs:

docker exec <container_name> cat /cron/last_code.txt

Output format: YYYY-MM-DD HH:MM:SS - 2FA Code: XXXXXX

## Persistence
Two Docker volumes are defined in docker-compose.yml to ensure data persists across restarts:

### seed-data -> Mounted at /data (Stores the decrypted seed)

### cron-output -> Mounted at /cron (Stores the audit logs)

## Security Disclosure
### EDUCATIONAL PURPOSE ONLY: This repository contains student_private.pem and student_public.pem committed to the codebase.

Why? This is a strict requirement for the assignment evaluation. The Docker container requires the private key to perform decryption during the grading process.

Risk: In a real-world production environment, private keys should NEVER be committed to version control. They should be injected via secret managers (e.g., AWS Secrets Manager, HashiCorp Vault).

Status: The keys in this repo should be considered compromised public knowledge and will not be used for any actual security identity beyond this academic task.

## Testing
To manually test the flow using curl:

1. Decrypt the seed (Assuming you have encrypted_seed.txt locally):

curl -X POST http://localhost:8080/decrypt-seed \
  -H "Content-Type: application/json" \
  -d "{\"encrypted_seed\": \"$(cat encrypted_seed.txt)\"}"
  
2. Get a Code:

curl http://localhost:8080/generate-2fa

3. Verify a Code:


curl -X POST http://localhost:8080/verify-2fa \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
