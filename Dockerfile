FROM python:3.11-slim

# libpcap for Scapy live capture; tcpdump for interface debugging
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src/       ./src/
COPY dashboard.html .

# Pre-train model at build time so container starts instantly
COPY src/train.py ./src/train.py
RUN python -m src.train

# Non-root user for demo mode (live capture needs --cap-add=NET_RAW)
RUN useradd -m nids
RUN chown -R nids:nids /app
USER nids

EXPOSE 8000

# Default: demo mode. Override with -e NIDS_DEMO=0 -e NIDS_INTERFACE=eth0
ENV NIDS_DEMO=1
ENV NIDS_INTERFACE=eth0
ENV NIDS_THRESHOLD=0.5

CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
