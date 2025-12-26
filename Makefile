.PHONY: test test-integration build build-linux conn profile-cbor install-proxy-systemd uninstall-debian docker-build docker-push docker-run docker-clean

GOMODCACHE ?= $(CURDIR)/.gomodcache
GOPATH ?= $(CURDIR)/.gopath
MACOSX_DEPLOYMENT_TARGET ?= 13.0
MACOSX_DEPLOYMENT_FLAGS := -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
ARCH ?= $(shell go env GOARCH)
BF ?= ./bin/bf

# Run Go tests for the single module.
test:
	@set -e; \
	echo "==> running tests"; \
	GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) \
	MACOSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET) \
	CGO_CFLAGS='$(MACOSX_DEPLOYMENT_FLAGS)' \
	CGO_LDFLAGS='$(MACOSX_DEPLOYMENT_FLAGS)' \
	go test ./...

test-integration:
	@set -e; \
	echo "==> running integration smoke test"; \
	GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) \
	MACOSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET) \
	CGO_CFLAGS='$(MACOSX_DEPLOYMENT_FLAGS)' \
	CGO_LDFLAGS='$(MACOSX_DEPLOYMENT_FLAGS)' \
	go test -tags integration ./socks5-daemon -run TestIntegrationQUIC -v

build:
	@./scripts/build-proto.sh

build-linux:
	@GOOS=linux GOARCH=$(ARCH) CGO_ENABLED=0 BIN_SUFFIX="-linux-$(ARCH)" ./scripts/build-proto.sh

conn-json:
	@PROXY_ADDR="$(PROXY_ADDR)"; \
	if [ -z "$$PROXY_ADDR" ]; then \
		echo "PROXY_ADDR is required (e.g. make conn PROXY_ADDR=1.2.3.4:9000)" >&2; \
		exit 1; \
	fi; \
	jq -c --arg proxy "$$PROXY_ADDR" '.proxy_addr = $$proxy | del(.obfuscation.server_private_key)' docs/examples/profile.json | base64

conn:
	@PROXY_ADDR="$(PROXY_ADDR)"; \
	if [ -z "$$PROXY_ADDR" ]; then \
		echo "PROXY_ADDR is required (e.g. make profile-cbor PROXY_ADDR=1.2.3.4:9000)" >&2; \
		exit 1; \
	fi; \
	jq -c --arg proxy "$$PROXY_ADDR" '.proxy_addr = $$proxy | del(.obfuscation.server_private_key)' docs/examples/profile.json | \
		$(BF) profile-cbor -base64

install-deps-debian:
	@set -e; \
	echo "==> installing dependencies"; \
	apt-get update; \
	apt-get install -y golang curl jq

gen-profile:
	@set -e; \
	echo "==> generating profile"; \
	IP=$$(curl -s https://ifconfig.me); \
	if [ -z "$$IP" ]; then \
		echo "failed to fetch public ip" >&2; \
		exit 1; \
	fi; \
	if ! ip addr | grep -q "$$IP"; then \
		echo "fetched ip $$IP does not match any local interface" >&2; \
		exit 1; \
	fi; \
	$(BF) create-profile --mtu 1420 --proxy-addr "$$IP:9000" > profile.json

install-proxy-systemd: gen-profile
	@set -e; \
	echo "==> installing proxy-server systemd unit + default configs"; \
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "run as root (e.g. sudo make install-proxy-systemd)" >&2; \
		exit 1; \
	fi; \
	install -d /etc/bridgefall; \
	install -m 0644 docs/examples/proxy-server.json /etc/bridgefall/proxy-server.json; \
	install -m 0644 profile.json /etc/bridgefall/profile.json; \
	install -m 0644 systemd/proxy-server.service /etc/systemd/system/proxy-server.service; \
	install -m 0755 bin/proxy-server /usr/local/bin/proxy-server; \
	cat profile.json | jq -c 'del(.obfuscation.server_private_key)' | $(BF) profile-cbor -base64 > /etc/bridgefall/client.txt; \
	chmod 644 /etc/bridgefall/client.txt; \
	systemctl daemon-reload; \
	systemctl enable --now proxy-server.service; \
	echo "==> proxy-server enabled and started"; \
	echo "==> client connection string saved to /etc/bridgefall/client.txt"

install-debian: install-deps-debian build install-proxy-systemd

uninstall-debian:
	@set -e; \
	echo "==> uninstalling proxy-server systemd unit + configs"; \
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "run as root (e.g. sudo make uninstall-debian)" >&2; \
		exit 1; \
	fi; \
	systemctl disable --now proxy-server.service || true; \
	rm -f /etc/systemd/system/proxy-server.service; \
	rm -f /usr/local/bin/proxy-server; \
	rm -rf /etc/bridgefall; \
	systemctl daemon-reload; \
	echo "==> proxy-server disabled and removed"

# Docker variables
DOCKER_IMAGE ?= ghcr.io/bridgefall/paniq-proxy-server
DOCKER_TAG ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "latest")
DOCKER_PLATFORM ?= linux/amd64
DOCKER_ARCH ?= $(word 2,$(subst /, ,$(DOCKER_PLATFORM)))

docker-build:
	@echo "==> building docker image $(DOCKER_IMAGE):$(DOCKER_TAG) ($(DOCKER_PLATFORM))"
	docker buildx build --platform=$(DOCKER_PLATFORM) \
		--build-arg TARGETARCH=$(DOCKER_ARCH) \
		--build-arg TARGETOS=linux \
		-t "$(DOCKER_IMAGE):$(DOCKER_TAG)" \
		-t "$(DOCKER_IMAGE):latest" \
		--load \
		.

docker-push:
	@echo "==> pushing docker image $(DOCKER_IMAGE):$(DOCKER_TAG) ($(DOCKER_PLATFORM))"
	docker buildx build --platform=$(DOCKER_PLATFORM) \
		--build-arg TARGETARCH=$(DOCKER_ARCH) \
		--build-arg TARGETOS=linux \
		-t "$(DOCKER_IMAGE):$(DOCKER_TAG)" \
		-t "$(DOCKER_IMAGE):latest" \
		--push \
		.

docker-run: docker-build
	@echo "==> running docker container"
	docker run --rm -it \
		-p 9000:9000/udp \
		-e BF_SERVER_PRIVATE_KEY="$${BF_SERVER_PRIVATE_KEY:-$$(openssl rand -base64 32)}" \
		-e GENERATE_CLIENT_CONN=true \
		"$(DOCKER_IMAGE):latest"

docker-clean:
	@echo "==> cleaning up docker resources"
	-docker rmi "$(DOCKER_IMAGE):$(DOCKER_TAG)" 2>/dev/null || true
	-docker rmi "$(DOCKER_IMAGE):latest" 2>/dev/null || true
