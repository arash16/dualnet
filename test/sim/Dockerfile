# The netsim test image: the real dualnet binary plus the `sim` helper (entrypoint init,
# simulated internet, traffic probes) on a slim Debian that carries the iproute2 + iptables
# tools dualnet's netcfg shells out to. Build from the repo root:
#   docker build -f test/sim/Dockerfile -t dualnet-sim:test .
# (The netsim engine builds this automatically.) This is separate from the production
# Dockerfile so the shipped image never carries test tooling.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/dualnet . \
    && CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/sim ./test/sim

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/dualnet /usr/local/bin/dualnet
COPY --from=build /out/sim /usr/local/bin/sim
# No ENTRYPOINT/CMD: the engine sets each container's command explicitly
# (`sim init -spec … -- dualnet -config …`, `sim echo`, or `sim probe …`).
