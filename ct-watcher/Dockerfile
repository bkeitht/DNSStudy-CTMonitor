# Multi-stage build for CertSpotter CLI
# Source: software.sslmate.com/src/certspotter

FROM golang:1.24-alpine AS builder

RUN CGO_ENABLED=0 go install software.sslmate.com/src/certspotter/cmd/certspotter@latest

# ---

FROM alpine:3.20

RUN apk add --no-cache bash curl jq ca-certificates

COPY --from=builder /go/bin/certspotter /usr/local/bin/certspotter

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY hook.sh /usr/local/bin/hook.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/hook.sh

RUN mkdir -p /var/lib/certspotter && \
    addgroup -S certspotter && \
    adduser -S certspotter -G certspotter && \
    chown -R certspotter:certspotter /var/lib/certspotter

USER certspotter

VOLUME ["/var/lib/certspotter"]

ENTRYPOINT ["entrypoint.sh"]
