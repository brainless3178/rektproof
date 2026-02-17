# ──────────────────────────────────────────────────────────
# Shanon GitHub Action — Container Image
# Builds the Shanon CLI + scanner from source
# ──────────────────────────────────────────────────────────

FROM rust:1.75-bookworm AS builder

WORKDIR /app
COPY . .

# Build release binaries
RUN cargo build --release -p shanon-cli -p shanon-guard -p program-analyzer && \
    strip target/release/shanon 2>/dev/null || true

# ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    jq \
    curl \
    ca-certificates \
    nodejs \
    npm \
    libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /app/target/release/shanon /usr/local/bin/shanon

# Copy action scripts
COPY shanon-action/entrypoint.sh /entrypoint.sh
COPY shanon-action/annotate.js /annotate.js
COPY shanon-action/package.json /package.json

# Install Node.js dependencies for PR annotation
RUN cd / && npm install --production 2>/dev/null

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
