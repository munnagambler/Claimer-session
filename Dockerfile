FROM python:3.11-slim

# Railway runs as root — no special user needed
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY server.py .
COPY dashboard.html .

# Persistent storage paths
# In Railway: Settings → Volumes → Mount Path: /data
ENV DB_PATH=/data/licenses.db
ENV SESSIONS_DIR=/data/sessions

# PORT is automatically set by Railway at runtime
# Gunicorn reads $PORT via shell expansion
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 1 --threads 8 --timeout 120 server:app"]
