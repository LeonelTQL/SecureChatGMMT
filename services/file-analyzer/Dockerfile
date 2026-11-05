FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav clamav-freshclam yara util-linux libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*
# Cambiar este argumento o usar --no-cache para renovar las firmas al reconstruir.
ARG CLAMAV_DB_REV=initial
RUN echo "$CLAMAV_DB_REV" > /var/lib/clamav/build-revision \
    && freshclam --stdout
COPY requirements.txt requirements-stego.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 analyzer
RUN mkdir -p /app/storage && chown analyzer:analyzer /app/storage && chmod 700 /app/storage
COPY app ./app
USER analyzer
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
