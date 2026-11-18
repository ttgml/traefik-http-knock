# Builds a Traefik image with the plugin baked in as a local plugin.
#
#   docker build -t ghcr.io/ttgml/traefik-http-knock:v0.4.3 .
#
# The plugin has no third-party dependencies, so no build stage is needed: the
# Go sources are copied verbatim into Traefik's fixed local-plugin directory and
# interpreted by Traefik's Yaegi loader at startup.
ARG TRAEFIK_VERSION=v3.2.5
FROM traefik:${TRAEFIK_VERSION} AS base

ARG PLUGIN_MODULE=github.com/ttgml/traefik-http-knock

COPY go.mod /plugins-local/src/${PLUGIN_MODULE}/go.mod
COPY .traefik.yml /plugins-local/src/${PLUGIN_MODULE}/.traefik.yml
# .dockerignore excludes *_test.go, so this copies every plugin source file.
COPY *.go /plugins-local/src/${PLUGIN_MODULE}/

# Static configuration used when the image is run standalone. On k3s the
# traefik chart mounts its own configuration file over this path, and the local
# plugin is enabled through additionalArguments instead.
COPY deploy/traefik-static-config.yml /etc/traefik/traefik.yml

RUN find /plugins-local -type d -exec chmod 0755 {} + \
 && find /plugins-local -type f -exec chmod 0644 {} +

# The end-to-end test bakes its configuration into the image instead of bind
# mounting the workspace: CI runners may execute the job inside a container
# whose paths do not exist on the Docker host, which turns bind mounts into
# empty directories. Build it with `--target e2e`.
FROM base AS e2e
COPY .github/e2e/traefik.yml /etc/traefik/traefik-compose.yml
COPY .github/e2e/dynamic.yml /etc/traefik/dynamic.yml

# Default target: the image that is published and deployed. Docker builds the
# last stage when no --target is given, so it must stay last.
FROM base AS production
