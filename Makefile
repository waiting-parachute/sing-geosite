fmt:
	@gofumpt -l -w .
	@gofmt -s -w .
	@gci write --custom-order -s standard -s "prefix(github.com/sagernet/)" -s "default" .

fmt_install:
	go install -v mvdan.cc/gofumpt@v0.8.0
	go install -v github.com/daixiang0/gci@latest

lint:
	golangci-lint run ./...

lint_install:
	go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0

test:
	go test -v ./...