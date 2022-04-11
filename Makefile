SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")


default: build


build:
	go build -o bin/vault-tools main.go

run:
	time (go run main.go --config ./griffin.yml secret/wefi)

checks: fmt-check

fmt-check:
	@test -z "$(shell gofmt -l $(SRC) | tee /dev/stderr)" || echo "[WARN] Fix formatting issues in with 'make fmt'"

.PHONY: build checks fmt-check
