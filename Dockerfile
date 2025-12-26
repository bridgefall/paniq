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

# Build the proxy-server binary (static for Alpine)
# Reduce parallelism to avoid OOM on resource-constrained systems
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    GOMAXPROCS=2 \
    go build \
    -ldflags="-s -w" \
    -o /tmp/proxy-server \
    ./proxy-server/cmd/proxy-server

# Verify the binary
RUN /tmp/proxy-server --help

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
COPY --from=builder /tmp/proxy-server /usr/local/bin/proxy-server
RUN chmod +x /usr/local/bin/proxy-server

# Copy default configs (templates)
COPY docs/examples/proxy-server.json /etc/bridgefall/proxy-server.json.template
COPY docs/examples/profile.json /etc/bridgefall/profile.json.template

# Copy entrypoint script with execute permissions
COPY --chmod=755 docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Switch to non-root user
USER bridgefall

# Expose the default UDP port
EXPOSE 9000/udp

# Health check (uses the binary with a simple check)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD pgrep -x proxy-server || exit 1

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command runs the proxy server
CMD ["--config", "/etc/bridgefall/proxy-server.json", "--profile", "/etc/bridgefall/profile.json"]
