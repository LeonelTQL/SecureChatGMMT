FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav clamav-freshclam yara util-linux libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*
ARG CLAMAV_DB_REV=initial
RUN echo "$CLAMAV_DB_REV" > /var/lib/clamav/build-revision && freshclam --stdout
COPY services/stego/requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt && useradd -r -u 10001 stego && mkdir /app/storage && chown stego:stego /app/storage
COPY services/stego/app ./app
COPY services/file-analyzer/app/__init__.py services/file-analyzer/app/analyzer.py \
    services/file-analyzer/app/image_validation.py services/file-analyzer/app/stego_adapter.py \
    services/file-analyzer/app/stego_lsb.py services/file-analyzer/app/antimalware.py \
    services/file-analyzer/app/clamav_scan.py services/file-analyzer/app/yara_scan.py \
    services/file-analyzer/app/scan_runner.py services/file-analyzer/app/exiftool_scan.py ./stego_diana/
COPY services/file-analyzer/app/rules ./stego_diana/rules
USER stego
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "/run/keys/tls-key.pem", "--ssl-certfile", "/run/keys/tls-cert.pem", "--limit-concurrency", "16", "--timeout-keep-alive", "5", "--no-access-log"]
