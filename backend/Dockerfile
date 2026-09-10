FROM python:3.11-slim

# System security hardening
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirement manifests first for layer caching
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt gunicorn redis psycopg2-binary

# Copy source code
COPY backend/ ./backend/
COPY . ./

WORKDIR /app/backend

ENV PORT=3000
ENV PYTHONUNBUFFERED=1

EXPOSE 3000

# High-concurrency Gunicorn workers (4 workers, 4 threads each)
CMD ["gunicorn", "--workers=4", "--threads=4", "--worker-class=gthread", "--bind=0.0.0.0:3000", "--timeout=120", "wsgi:app"]
