# Build stage (use Debian for stable builds)
FROM golang:1.23-bookworm AS builder

# Build arguments for target architecture
ARG TARGETARCH=amd64
ARG TARGETOS=linux

# Set working directory
WORKDIR /build

# Copy go modules files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the paniq-proxy binary (static for Alpine)
# Reduce parallelism to avoid OOM on resource-constrained systems
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    GOMAXPROCS=2 \
    go build \
    -ldflags="-s -w" \
    -o /tmp/paniq-proxy \
    ./cmd/paniq-proxy

# Verify the binary
RUN /tmp/paniq-proxy --help

# Runtime stage (Alpine for small image size)
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    jq \
    bash \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 bridgefall && \
    adduser -D -u 1000 -G bridgefall -s /bin/sh bridgefall

# Create config directory
RUN mkdir -p /etc/bridgefall && \
    chown -R bridgefall:bridgefall /etc/bridgefall

# Copy binary from builder
COPY --from=builder /tmp/paniq-proxy /usr/local/bin/paniq-proxy
RUN chmod +x /usr/local/bin/paniq-proxy

# Copy default configs (templates)
COPY docs/examples/paniq-proxy.json /etc/bridgefall/paniq-proxy.json.template
COPY docs/examples/profile.json /etc/bridgefall/profile.json.template

# Copy entrypoint script with execute permissions
COPY --chmod=755 internal/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Switch to non-root user
USER bridgefall

# Expose the default UDP port
EXPOSE 9000/udp

# Health check (uses the binary with a simple check)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD pgrep -x paniq-proxy || exit 1

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command runs the proxy server
CMD ["--config", "/etc/bridgefall/paniq-proxy.json", "--profile", "/etc/bridgefall/profile.json"]
