# BTCPay Server with curl added for the container healthcheck.
FROM docker.io/btcpayserver/btcpayserver:2.2.1
USER root
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
