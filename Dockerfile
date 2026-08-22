# Build a static dualnet binary, then ship it on a slim Debian runtime that has
# the iproute2 + iptables tools the relay uses for tunnel setup and NAT. Debian's
# iptables uses the nft backend, matching a modern Ubuntu/k3s host (important when
# running with hostNetwork, where the relay edits the host's firewall).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /dualnet .

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /dualnet /usr/local/bin/dualnet
ENTRYPOINT ["dualnet"]
# Args are supplied by the deployment (e.g. -config /etc/dualnet/node.yaml); see deploy/k8s.
CMD ["-h"]
