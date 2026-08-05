FROM python:3.11-slim

LABEL maintainer="PQC Compliance"
LABEL description="Post-Quantum Cryptography Compliance Validator"

WORKDIR /opt/pqc-validator

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy application
COPY requirements.txt .
COPY main.py .
COPY src/ ./src/
COPY config/ ./config/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create directories for logs and reports
RUN mkdir -p /var/log/pqc-validator /var/log/pqc-reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PQC_LOG_DIR=/var/log/pqc-validator
ENV PQC_REPORT_DIR=/var/log/pqc-reports

# Default entry point
ENTRYPOINT ["python3", "main.py"]
CMD ["--log-dir", "/var/log/pqc-validator", "--report-dir", "/var/log/pqc-reports"]
