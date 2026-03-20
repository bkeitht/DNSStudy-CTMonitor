# Multi-stage build for certstream-server-go
# Source: github.com/bkeitht/certstream-server-go (fork of d-Rickyy-b/certstream-server-go)

FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
RUN git clone --branch v1.9.0-beta.3 --depth 1 \
    https://github.com/bkeitht/certstream-server-go.git .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o certstream-server ./cmd/certstream-server-go

# ---

FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget \
    && addgroup -S certstream \
    && adduser -S certstream -G certstream

COPY --from=builder /build/certstream-server /usr/local/bin/certstream-server
COPY config.yml /etc/certstream/config.yml

RUN mkdir -p /data && chown certstream:certstream /data

USER certstream

EXPOSE 8080 9090

VOLUME ["/data"]

ENTRYPOINT ["certstream-server", "-config", "/etc/certstream/config.yml"]
