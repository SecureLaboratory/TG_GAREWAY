# Gateway image: no isolated-browser stream client, so the build doesn't pull the 1.3 GB
# browser image and works the same on x86 and ARM.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends libmagic1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
# Tolerate slow or flaky networks (VMs, VPNs): longer timeout per download, more retries.
ENV PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=10 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . .
RUN useradd --system --uid 10001 tgv && mkdir -p /data/browsers && chown -R tgv /data
USER tgv

# Release version shown on the login screen (set by the image build: --build-arg TGV_VERSION=1.8).
ARG TGV_VERSION=dev
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data TGV_BUILD_VERSION=$TGV_VERSION
EXPOSE 8080
CMD ["uvicorn", "tgviewer.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--no-server-header"]
