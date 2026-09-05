.PHONY: help build run run-debug test test-race coverage clean enroll-est fetch-intermediate check-ocsp fetch-crl revoke-cert metrics docker-build docker-up docker-down docker-logs

# Default target
help:
	@echo "go-certa - Certificate Authority & PKI Operations"
	@echo "=================================================="
	@echo "make run               - Start the CA server (http://localhost:8080)"
	@echo "make run-debug         - Start the CA server with Swagger UI enabled (/swagger/)"
	@echo "make build             - Compile server binary into bin/"
	@echo "make test              - Run all unit and integration tests"
	@echo "make test-race         - Run tests with race condition detector"
	@echo "make coverage          - Generate test coverage report"
	@echo "make fetch-intermediate- Download intermediate CA certificate from /ca/intermediate.crt"
	@echo "make enroll-est        - Generate CSR and enroll test certificate via EST"
	@echo "make check-ocsp        - Query OCSP responder for certificate status"
	@echo "make fetch-crl         - Download and inspect CRL from /crl/intermediate.crl"
	@echo "make revoke-cert       - Revoke certificate (specify SERIAL=<hex_or_dec> REASON=<1-5>)"
	@echo "make metrics           - Query Prometheus metrics from /metrics"
	@echo "make docker-build      - Build Docker container image"
	@echo "make docker-up         - Start service in background using Docker Compose"
	@echo "make docker-down       - Stop Docker Compose service"
	@echo "make docker-logs       - Tail Docker Compose logs"
	@echo "make clean             - Clean build outputs and temporary keys/certificates"

# Build & Run
build:
	@go build -o bin/certa-server ./cmd/certa-server/

run:
	@go run ./cmd/certa-server/

run-debug:
	@CERTA_ENABLE_SWAGGER=true go run ./cmd/certa-server/

# Testing
test:
	@go test -v -count=1 ./...

test-race:
	@go test -race -count=1 ./...

coverage:
	@go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out

# Docker operations
docker-build:
	@docker build -t go-certa:latest .

docker-up:
	@docker compose up -d

docker-down:
	@docker compose down

docker-logs:
	@docker compose logs -f

# Operational PKI commands
fetch-intermediate:
	@echo "--> Fetching Intermediate CA certificate..."
	@curl -s http://localhost:8080/ca/intermediate.crt --output intermediate.der
	@openssl x509 -in intermediate.der -inform der -text -noout

enroll-est:
	@echo "--> Generating client key and CSR..."
	@openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=client.example.com"
	@openssl req -in client.csr -outform der | base64 > client.b64
	@echo "--> Submitting CSR to EST /simpleenroll..."
	@curl -s -X POST -d @client.b64 http://localhost:8080/.well-known/est/simpleenroll --output client.der
	@echo "--> Enrolled Certificate:"
	@openssl x509 -in client.der -inform der -text -noout

check-ocsp:
	@if [ ! -f intermediate.der ]; then $(MAKE) fetch-intermediate; fi
	@echo "--> Querying OCSP Responder..."
	@openssl ocsp -issuer intermediate.der -cert client.der -url http://localhost:8080/ocsp -text

fetch-crl:
	@echo "--> Fetching CRL from /crl/intermediate.crl..."
	@curl -s http://localhost:8080/crl/intermediate.crl --output intermediate.crl
	@openssl crl -inform der -in intermediate.crl -text -noout

revoke-cert:
	@if [ -z "$(SERIAL)" ]; then echo "Error: Please specify SERIAL=<serial_number>"; exit 1; fi
	@echo "--> Submitting revocation for serial $(SERIAL)..."
	@curl -s -X POST http://localhost:8080/api/v1/revoke \
		-H "Content-Type: application/json" \
		-d "{\"serial\": \"$(SERIAL)\", \"reason\": $${REASON:-1}}"
	@echo ""

metrics:
	@curl -s http://localhost:8080/metrics

clean:
	@rm -f bin/* client.key client.csr client.b64 client.der intermediate.der intermediate.crl coverage.out
