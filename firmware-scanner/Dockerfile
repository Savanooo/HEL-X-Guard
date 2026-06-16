# HELİX-Guard Firmware Scanner — Docker Image
#
# Security model:
#   - Non-root user (UID 1000)
#   - Intended to be run with: --network none --read-only --tmpfs /tmp
#   - Extracted files are never executed by the scanner code
#
# Build:
#   docker build -t helix-guard-scanner:latest .
#
# Run:
#   docker run --rm \
#     --network none --read-only --tmpfs /tmp:size=256m \
#     --memory 1g --cpus 1 \
#     -v /path/to/firmware.bin:/input/firmware.bin:ro \
#     -v /path/to/output:/output \
#     helix-guard-scanner:latest \
#     /input/firmware.bin --output /output/report.json

FROM python:3.11-slim

LABEL org.opencontainers.image.title="HELİX-Guard Scanner"
LABEL org.opencontainers.image.description="Static firmware binary security analysis"
LABEL org.opencontainers.image.version="0.1.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system tools + build deps for yara-python, then strip build deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        make \
        automake \
        libtool \
        pkg-config \
        file \
        binwalk \
        yara \
        libyara-dev \
        binutils \
    && pip install --no-cache-dir click yara-python \
    # Strip build-only packages to reduce image size
    && apt-get purge -y --auto-remove \
        gcc make automake libtool pkg-config libyara-dev \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

# Copy package definition first (layer cache friendly)
COPY pyproject.toml .

# Copy scanner source and rules
COPY src/ src/
COPY rules/ rules/

# Install scanner package (no additional deps — already installed above)
RUN pip install --no-cache-dir --no-deps -e .

# Create non-root user for running analysis
RUN useradd -m -u 1000 -s /bin/sh scanner \
    && chown -R scanner:scanner /app

USER scanner

# Input and output mount points (host binds these at runtime)
VOLUME ["/input", "/output"]

ENTRYPOINT ["firmware-scan"]
CMD ["--help"]
