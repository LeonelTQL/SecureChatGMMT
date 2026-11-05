FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt && useradd -r -u 10001 stego && mkdir /app/storage && chown stego:stego /app/storage
COPY app ./app
USER stego
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "/run/keys/tls-key.pem", "--ssl-certfile", "/run/keys/tls-cert.pem", "--limit-concurrency", "16", "--timeout-keep-alive", "5", "--no-access-log"]
