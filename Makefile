.PHONY: help example test clean

help:
	@echo "Available targets:"
	@echo "  example    - Build the example binary"
	@echo "  test       - Run tests"
	@echo "  clean      - Remove built binaries"

example:
	@echo "Building example binary..."
	go build -o bluecat-example ./cmd/example
	@echo "✓ Built: ./bluecat-example"
	@echo ""
	@echo "Run with: ./bluecat-example -h for help"

test:
	go test -v ./...

clean:
	rm -f bluecat-example
	@echo "✓ Cleaned"
