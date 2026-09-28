# syntax=docker/dockerfile:1

# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
# Standard Dockerfile for running the tool in isolated environments.

FROM python:3.11-slim-bookworm

# Set environment variables to prevent Python from writing .pyc files and buffer outputs.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Suppress Streamlit's telemetry and email prompt
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_GATHER_USAGE_STATS=false

WORKDIR /opt/ecdat

# Install system dependencies.
# `curl` is NOT optional decoration here: the HEALTHCHECK below invokes it, and python:3.11-slim
# does not ship curl. Without this line the image builds cleanly and then reports itself unhealthy
# forever, which is the worst possible failure -- it looks like the app is broken when it is only
# the probe that is. `ca-certificates` is what lets pip reach PyPI over TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the project. `.dockerignore` is what keeps the third-party benchmark corpora -- cloned
# checkouts of paramiko and golang.org/x/crypto, hundreds of MB -- out of the image; without it
# `COPY . .` would ship someone else's source code inside our image.
COPY . .

# Create a generic volume mount point for targets
VOLUME ["/target"]

# Expose Streamlit port
EXPOSE 8501

# Add a healthcheck for the Streamlit UI
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl --fail --silent http://localhost:8501/_stcore/health || exit 1

# Default command: launch the interactive UI
CMD ["streamlit", "run", "app.py"]
