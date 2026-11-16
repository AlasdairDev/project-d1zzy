# Minimal Tor sidecar publishing the app as a v3 onion service.
FROM docker.io/library/alpine:3.22
RUN apk add --no-cache tor su-exec
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
