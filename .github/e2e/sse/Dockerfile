# Streaming backend for the end-to-end test. The binary is static, so the final
# image needs nothing but the binary and the scratch image needs no pull.
FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /sse .

FROM scratch

COPY --from=build /sse /sse
ENTRYPOINT ["/sse"]
