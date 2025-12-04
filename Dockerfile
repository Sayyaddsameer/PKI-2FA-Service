# Stage 1: Builder
FROM python:3.11-slim as builder
WORKDIR /app

# Copy dependency file
COPY requirements.txt .

# Install dependencies (optimize for caching)
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim
WORKDIR /app

# Install system dependencies (cron, timezone tools)
RUN apt-get update && apt-get install -y cron tzdata && \
    rm -rf /var/lib/apt/lists/*

# Set timezone to UTC (Critical!)
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Copy dependencies from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY cron/ ./cron/

# Copy Keys (Required for Docker to function)
# The evaluator needs these to verify your work inside the container
COPY student_private.pem .
COPY student_public.pem .
COPY instructor_public.pem .

# Setup cron job
# 1. Move file to system cron directory
# 2. Set permissions (0644 is strict requirement for cron)
# 3. Register with crontab
RUN cp cron/2fa-cron /etc/cron.d/2fa-cron && \
    chmod 0644 /etc/cron.d/2fa-cron && \
    crontab /etc/cron.d/2fa-cron

# Create volume mount points
# We create the folders so Docker can mount volumes to them
RUN mkdir -p /data /cron && \
    chmod 755 /data /cron && \
    chmod +x scripts/log_2fa_cron.py

# Expose port 8080
EXPOSE 8080

# Start cron service and API server
# We run cron in background and uvicorn in foreground
CMD cron && uvicorn app.main:app --host 0.0.0.0 --port 8080