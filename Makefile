.PHONY: help
help:  ## This help
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: clean  ## Build the binary
	@go build -ldflags="-s -w"

.PHONY: clean
clean:  ## Clean workspace
	@rm -rf coverage.out

.PHONY: install
install:  ## Install project dependencies
	@go mod download

.PHONY: watch
watch:  ## Watch for file changes and run the example.
	@bash -c "find . -name '*.go' | grep -v 'misc' | entr -r go run examples/main.go"

.PHONY: watchtests
watchtests:  ## Watch for file changes and run tests.
	@bash -c "find . -name '*.go' | grep -v 'misc' | entr -r go test -v -cover auth.go auth_test.go"

.PHONY: test
test: clean  ## Run tests.
	@go clean -testcache; go test auth.go auth_test.go -v -covermode=atomic -coverprofile coverage.out; go tool cover -func coverage.out
