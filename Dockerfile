FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /rib-ingester ./cmd/rib-ingester

FROM alpine:3.20
COPY --from=builder /rib-ingester /usr/local/bin/rib-ingester
ENTRYPOINT ["rib-ingester"]
