FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git
WORKDIR /src
RUN git clone --branch fix/raw-initiation-speaker-ip --depth 1 https://github.com/pobradovic08/gobmp.git .
RUN CGO_ENABLED=0 go build -o /gobmp ./cmd/gobmp

FROM alpine:3.20
COPY --from=builder /gobmp /gobmp
ENV GOMAXPROCS=1
ENTRYPOINT ["/gobmp"]
