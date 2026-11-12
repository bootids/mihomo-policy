.PHONY: test check build release validate

test:
	go test -race ./...

check:
	go vet ./...
	go test ./...

build:
	go build -trimpath -o bin/mihomo-policy ./cmd/mihomo-policy

validate:
	go run ./cmd/mihomo-policy validate --policy policy/policy.yaml --cases tests/routing-cases.yaml

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/mihomo-policy-linux-amd64 ./cmd/mihomo-policy
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/mihomo-policy-linux-arm64 ./cmd/mihomo-policy
