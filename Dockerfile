FROM golang:1.17 AS builder
WORKDIR /go/src/github.com/dathan/go-vault-dump/
COPY ./ .
RUN make build

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /opt/vault-tools
COPY --from=builder /go/src/github.com/dathan/go-vault-dump/bin/vault-tools .