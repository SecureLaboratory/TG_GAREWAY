FROM python:3.12-slim
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir "docker~=7.2" "fastapi~=0.162.0" "uvicorn~=0.54.0"
WORKDIR /app
COPY app.py .
ENV PYTHONUNBUFFERED=1
# Needs the Docker socket (root). Keep this service tiny and unreachable from outside.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000", "--no-server-header"]
