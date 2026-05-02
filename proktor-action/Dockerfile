# ──────────────────────────────────────────────────────────
# Proktor GitHub Action — Container Image
# Builds the Proktor CLI + scanner from source
# ──────────────────────────────────────────────────────────

FROM rust:1.75-bookworm AS builder

WORKDIR /app
COPY . .

# Build release binaries
RUN cargo build --release -p proktor-cli -p proktor-guard -p program-analyzer && \
    strip target/release/proktor 2>/dev/null || true

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
COPY --from=builder /app/target/release/proktor /usr/local/bin/proktor

# Copy action scripts
COPY proktor-action/entrypoint.sh /entrypoint.sh
COPY proktor-action/annotate.js /annotate.js
COPY proktor-action/package.json /package.json

# Install Node.js dependencies for PR annotation
RUN cd / && npm install --production 2>/dev/null

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
