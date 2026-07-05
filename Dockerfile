# Specie - Counter-Threat-Finance Attribution & Fusion Platform.
# Pure-Python stdlib project (zero runtime dependencies).
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Specie" \
      org.opencontainers.image.description="Counter-Threat-Finance Attribution & Fusion Platform" \
      org.opencontainers.image.source="https://github.com/cognis-digital/cognis-lattice" \
      org.opencontainers.image.licenses="COCL-1.0" \
      org.opencontainers.image.vendor="Cognis Digital LLC"

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir .

ENTRYPOINT ["specie"]
CMD ["--help"]
