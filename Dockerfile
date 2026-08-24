FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ .

# Create certs directory
RUN mkdir -p /app/certs

# Port 80  — ACME http-01 challenge (temporary, only during cert request)
# Port 8443 — HTTPS API endpoint
EXPOSE 80 8443

CMD ["python", "main.py"]
