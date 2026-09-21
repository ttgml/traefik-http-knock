# Modules
MODULE              ?= github.com/ttgml/traefik-http-knock
TRAEFIK_VERSION     ?= v3.2
IMAGE               ?= ghcr.io/ttgml/traefik-http-knock
TAG                 ?= v0.1.1
PLUGIN_VERSION      ?= v0.1.1
# The plugin ConfigMap must live in the same namespace as the Traefik pod.
K8S_NAMESPACE       ?= kube-system
PLUGIN_CONFIGMAP    ?= http-knock-plugin
REDIS_IMAGE         ?= redis:7.4-alpine
REDIS_PASSWORD      ?= devpassword
GO                  ?= go

PLUGIN_SOURCES = go.mod .traefik.yml knock.go ip.go redis.go

.PHONY: help
help:
	@echo "Targets:"
	@echo "  fmt vet test race check      local quality gates"
	@echo "  tidy                         go mod tidy"
	@echo "  docker-build                 build the Traefik image with the plugin"
	@echo "  compose-up compose-down      local Traefik + Redis + whoami demo"
	@echo "  redis-up redis-down          throwaway Redis for the integration test"
	@echo "  test-integration             Redis integration test (needs redis-up)"
	@echo "  k8s-plugin-configmap         generate deploy/plugin-configmap.yaml"
	@echo "  release                      checks + annotated git tag TAG"

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: test
test:
	$(GO) test ./...

.PHONY: race
race:
	$(GO) test -race ./...

.PHONY: check
check:
	@test -z "$$(gofmt -l .)" || (echo "unformatted files:"; gofmt -l .; exit 1)
	$(GO) vet ./...
	$(GO) test ./...
	$(GO) test -race ./...

.PHONY: docker-build
docker-build:
	docker build \
		--build-arg TRAEFIK_VERSION=$(TRAEFIK_VERSION) \
		--build-arg PLUGIN_MODULE=$(MODULE) \
		-t $(IMAGE):$(TAG) \
		-t $(IMAGE):latest \
		.

.PHONY: compose-up
compose-up:
	docker compose up -d --build

.PHONY: compose-down
compose-down:
	docker compose down -v

.PHONY: redis-up
redis-up:
	docker run --rm -d --name knock-redis -p 6379:6379 \
		$(REDIS_IMAGE) redis-server --requirepass $(REDIS_PASSWORD)

.PHONY: redis-down
redis-down:
	docker rm -f knock-redis

.PHONY: test-integration
test-integration:
	REDIS_ADDR=127.0.0.1:6379 REDIS_PASSWORD=$(REDIS_PASSWORD) \
		$(GO) test -run Integration -v ./...

# Generates the ConfigMap that carries the plugin source into a k3s cluster
# without building a custom image. The plugin source is not committed in a
# ConfigMap because it duplicates the repository contents.
.PHONY: k8s-plugin-configmap
k8s-plugin-configmap:
	kubectl create configmap $(PLUGIN_CONFIGMAP) -n $(K8S_NAMESPACE) \
		--from-file=go.mod \
		--from-file=.traefik.yml \
		--from-file=knock.go \
		--from-file=ip.go \
		--from-file=redis.go \
		--dry-run=client -o yaml \
		> deploy/plugin-configmap.yaml
	@echo "wrote deploy/plugin-configmap.yaml (namespace $(K8S_NAMESPACE))"

.PHONY: release
release: check
	@echo "tagging $(PLUGIN_VERSION)"
	git tag -a $(PLUGIN_VERSION) -m "traefik-http-knock $(PLUGIN_VERSION)"
	@echo "push with: git push origin $(PLUGIN_VERSION)"
