# --- Builder --- #
FROM golang:1-bookworm AS builder

WORKDIR /usr/src/app

COPY . .
RUN go mod download && go mod verify
RUN go build -o /usr/src/app/ssh-proxy .

# --- Image --- #
FROM debian:bookworm-slim
COPY --from=builder /usr/src/app/ssh-proxy /usr/local/bin/ssh-proxy
# The configuration file, /etc/ssh-proxy.yaml, is expected to be mounted from a configmap
CMD ["ssh-proxy"]
