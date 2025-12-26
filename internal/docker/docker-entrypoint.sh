#!/bin/bash
set -euo pipefail

# Config file paths
PROXY_SERVER_CONFIG="${PROXY_SERVER_CONFIG:-/etc/bridgefall/paniq-proxy.json}"
PROFILE_CONFIG="${PROFILE_CONFIG:-/etc/bridgefall/profile.json}"
PROXY_SERVER_TEMPLATE="/etc/bridgefall/paniq-proxy.json.template"
PROFILE_TEMPLATE="/etc/bridgefall/profile.json.template"

# Function to substitute environment variables in JSON
substitute_env() {
    local file="$1"
    local output="$2"
    # Use jq to safely handle JSON, substituting known env vars
    if [[ -f "$file" ]]; then
        cp "$file" "$output"
    fi
}

# Generate proxy-server config if it doesn't exist
if [[ ! -f "$PROXY_SERVER_CONFIG" ]]; then
    echo "==> Generating proxy-server config from template..."
    if [[ -f "$PROXY_SERVER_TEMPLATE" ]]; then
        substitute_env "$PROXY_SERVER_TEMPLATE" "$PROXY_SERVER_CONFIG"

        # Apply environment variable overrides for common settings
        if [[ -n "${LISTEN_ADDR:-}" ]]; then
            jq --arg addr "$LISTEN_ADDR" '.listen_addr = $addr' "$PROXY_SERVER_CONFIG" > "${PROXY_SERVER_CONFIG}.tmp"
            mv "${PROXY_SERVER_CONFIG}.tmp" "$PROXY_SERVER_CONFIG"
        fi

        if [[ -n "${WORKERS:-}" ]]; then
            jq --arg workers "$WORKERS" '.workers = ($workers | tonumber)' "$PROXY_SERVER_CONFIG" > "${PROXY_SERVER_CONFIG}.tmp"
            mv "${PROXY_SERVER_CONFIG}.tmp" "$PROXY_SERVER_CONFIG"
        fi

        if [[ -n "${MAX_CONNECTIONS:-}" ]]; then
            jq --arg conns "$MAX_CONNECTIONS" '.max_connections = ($conns | tonumber)' "$PROXY_SERVER_CONFIG" > "${PROXY_SERVER_CONFIG}.tmp"
            mv "${PROXY_SERVER_CONFIG}.tmp" "$PROXY_SERVER_CONFIG"
        fi

        if [[ -n "${LOG_LEVEL:-}" ]]; then
            jq --arg level "$LOG_LEVEL" '.log_level = $level' "$PROXY_SERVER_CONFIG" > "${PROXY_SERVER_CONFIG}.tmp"
            mv "${PROXY_SERVER_CONFIG}.tmp" "$PROXY_SERVER_CONFIG"
        fi
    else
        echo "ERROR: No proxy-server config found and no template available"
        exit 1
    fi
fi

# Generate profile config if it doesn't exist
if [[ ! -f "$PROFILE_CONFIG" ]]; then
    echo "==> Generating profile config from template..."
    if [[ -f "$PROFILE_TEMPLATE" ]]; then
        # Check if we should use auto-generated proxy address
        if [[ -n "${PROXY_ADDR:-}" ]]; then
            jq --arg addr "$PROXY_ADDR" '.proxy_addr = $addr' "$PROFILE_TEMPLATE" > "${PROFILE_CONFIG}.tmp"
            mv "${PROFILE_CONFIG}.tmp" "$PROFILE_CONFIG"
        else
            cp "$PROFILE_TEMPLATE" "$PROFILE_CONFIG"
        fi

        # Inject server private key from environment if provided
        if [[ -n "${BF_SERVER_PRIVATE_KEY:-}" ]]; then
            echo "==> Injecting server private key from environment..."
            jq --arg key "$BF_SERVER_PRIVATE_KEY" '.obfuscation.server_private_key = $key' "$PROFILE_CONFIG" > "${PROFILE_CONFIG}.tmp"
            mv "${PROFILE_CONFIG}.tmp" "$PROFILE_CONFIG"
        else
            # Check if template already has a key (useful for development)
            if ! jq -e '.obfuscation.server_private_key' "$PROFILE_CONFIG" > /dev/null 2>&1; then
                echo "WARNING: No server private key found. Generate one with:"
                echo "  openssl rand -base64 32"
                echo "Or set BF_SERVER_PRIVATE_KEY environment variable."
            fi
        fi
    else
        echo "ERROR: No profile config found and no template available"
        exit 1
    fi
fi

# Generate and display client connection string if requested
if [[ "${GENERATE_CLIENT_CONN:-false}" == "true" ]]; then
    echo "==> Generating client connection string..."
    if command -v jq &> /dev/null; then
        CLIENT_JSON=$(jq -c 'del(.obfuscation.server_private_key)' "$PROFILE_CONFIG")
        echo "Client profile (base64):"
        echo "$CLIENT_JSON" | base64 -w0
        echo ""
    fi
fi

# Display server public key for easy client configuration
if command -v jq &> /dev/null; then
    SERVER_PUBLIC_KEY=$(jq -r '.obfuscation.server_public_key // empty' "$PROFILE_CONFIG")
    if [[ -n "$SERVER_PUBLIC_KEY" ]]; then
        echo "==> Server public key: $SERVER_PUBLIC_KEY"
    fi
fi

# Run the proxy server with any provided arguments
echo "==> Starting paniq-proxy..."
exec /usr/local/bin/paniq-proxy "$@"
