# ──────────────────────────────────────────────────────────
# Proktor — Solana Security Platform
# Multi-stage Docker build
# ──────────────────────────────────────────────────────────

FROM rust:1.75-bookworm AS builder

WORKDIR /app
COPY . .

# Build the CLI binary and core libraries
RUN cargo build --release -p proktor-cli -p proktor-guard -p program-analyzer

# ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Copy built binaries
COPY --from=builder /app/target/release/proktor /usr/local/bin/proktor

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s CMD proktor --version || exit 1

ENTRYPOINT ["proktor"]
CMD ["--help"]
