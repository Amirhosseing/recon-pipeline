# Recon Pipeline - Dockerfile
# Installs Python app + all Go-based security tools into a single image.

FROM golang:1.24-bookworm AS go-builder

# Allow Go to auto-download newer toolchains required by tools
ENV GOTOOLCHAIN=auto

# Install all Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/d3mondev/puredns/v2@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest \
    && go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && go install -v github.com/sensepost/gowitness@latest

# Download Nuclei templates
RUN nuclei -update-templates

# ---------------------------------------------------------------------------

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies + nmap + chromium + massdns build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    nmap \
    chromium \
    ca-certificates \
    git \
    make \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install massdns (required by puredns)
RUN git clone https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && cd /tmp/massdns \
    && make \
    && cp bin/massdns /usr/local/bin/ \
    && rm -rf /tmp/massdns

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Go binaries from builder AFTER pip install to avoid Python httpx
# overwriting the Go httpx binary (openai depends on Python httpx package)
COPY --from=go-builder /go/bin/* /usr/local/bin/

# Copy Nuclei templates
COPY --from=go-builder /root/nuclei-templates /root/nuclei-templates

# Copy application code
COPY . .

# Create scans directory
RUN mkdir -p scans

# Expose Flask port
EXPOSE 5000

# Environment variables (override in docker-compose or at runtime)
ENV SECRET_KEY="change-me-in-production"
ENV ADMIN_USER="administrator"
ENV ADMIN_PASS="change-me-in-production"
ENV MONGO_URI="mongodb://mongo:27017/"
ENV DB_NAME="recon_pipeline"
ENV TELEGRAM_BOT_TOKEN=""
ENV TELEGRAM_CHAT_ID=""
ENV CHROME_BIN="/usr/bin/chromium"

# Run the application
CMD ["python", "app.py"]
