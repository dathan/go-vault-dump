FROM golang:1.15
RUN apt-get -qq update && apt-get -yqq install upx
ENV GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64

WORKDIR /src
COPY ./ .
RUN go mod download && \
  go build \
  -a \
  -trimpath \
  -ldflags "-s -w -extldflags '-static'" \
  -tags 'osusergo netgo static_build' \
  -o /bin/vault-dump \
  . && \
  strip /bin/vault-dump && \
  upx -q -9 /bin/vault-dump
