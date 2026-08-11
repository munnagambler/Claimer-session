FROM python:3.11-slim

# Create a non-root user for Hugging Face compatibility (UID 1000)
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:${PATH}"

WORKDIR /app

# Install dependencies as non-root user
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy application files with correct ownership
COPY --chown=user server.py .
COPY --chown=user dashboard.html .

# Hugging Face persistent storage paths
ENV DB_PATH=/data/licenses.db
ENV SESSIONS_DIR=/data/sessions

# Hugging Face handles creating the /data directory with correct permissions.
# Your Python app should handle creating subdirectories like /data/sessions 
# at startup using os.makedirs(os.getenv('SESSIONS_DIR'), exist_ok=True)

EXPOSE 7860

CMD ["gunicorn", "--bind", "0.0.0.0:7860", "--workers", "1", "--threads", "8", "--timeout", "120", "server:app"]