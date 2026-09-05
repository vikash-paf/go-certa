# Interactive API Console & OpenAPI Specification (Swagger UI)

`go-certa` includes a fully embedded, zero-dependency **OpenAPI 3.0 specification** and **Swagger UI** console to visually inspect endpoints, test certificate enrollment and revocations, and generate client SDKs.

---

## 🔒 Security Architecture: Gated Behind a Flag

In real-world commercial Certificate Authorities (e.g. DigiCert, Let's Encrypt, Sectigo) and regulated enterprise PKIs:
* **Attack Surface Minimization**: High-security signing cores intentionally disable interactive exploration consoles and debug endpoints on public networks to prevent denial-of-service or brute-force scanning.
* **Separation of Planes**: Operational administration (e.g., manual revocations or inventory inspection) is kept on an internal management plane, while public ports only accept the strict binary/TLS protocol packets (ACME port 80/443, OCSP, CDP).

Therefore, in `go-certa`, **Swagger UI is disabled by default** (`404 Not Found`). It is activated only when explicitly requested via CLI flag or environment variable.

---

## 🚀 Enabling Swagger UI

### 1. Locally via Makefile or CLI
```bash
# Using Makefile
make run-debug

# Or using environment variable
CERTA_ENABLE_SWAGGER=true go run ./cmd/certa-server/

# Or using CLI flag
go run ./cmd/certa-server/ --swagger
# or
go run ./cmd/certa-server/ --debug
```

### 2. In Docker Compose
In [`docker-compose.yml`](file:///P:/GITHUB/go-certa/docker-compose.yml), set the environment variable:
```yaml
    environment:
      - CERTA_DATA_DIR=/data
      - CERTA_LISTEN_ADDR=:8080
      - CERTA_BASE_URL=http://localhost:8080
      - CERTA_ENABLE_SWAGGER=true
```
Then start the container:
```bash
docker compose up -d
```

---

## 🌐 Endpoints

Once enabled, navigate to:
* **Interactive UI**: `http://localhost:8080/swagger/`
* **Raw OpenAPI 3.0 Spec**: `http://localhost:8080/swagger/doc.json`

---

## 🛠️ Exploring PKI Endpoints in Swagger UI

The Swagger console categorizes endpoints by PKI function:

### 1. Management & Revocation API (`POST /api/v1/revoke`)
* Click **Try it out**.
* Input JSON payload:
  ```json
  {
    "serial": "4a7f29c0b1e388d2",
    "reason": 1
  }
  ```
* Standard **RFC 5280 §5.3.1 Reason Codes**:
  * `0` = `unspecified`
  * `1` = `keyCompromise` (Private key stolen or leaked)
  * `2` = `cACompromise` (Issuing CA authority key compromised)
  * `3` = `affiliationChanged` (Subject name/organization changed)
  * `4` = `superseded` (Replaced by a newer certificate)
  * `5` = `cessationOfOperation` (Service or server decommissioned)
* Click **Execute** and review the immediate JSON response confirming revocation.

### 2. Real-Time Status via OCSP (`GET /ocsp/{request}` & `POST /ocsp`)
* Inspect the RFC 5019 HTTP GET parameters and response headers (`Cache-Control: public, max-age=3600`, `ETag`).
* Review how relying parties validate revocation status before connecting.

### 3. Automated Enrollment (`POST /.well-known/est/simpleenroll`)
* Submit a base64-encoded PKCS#10 CSR directly in the request body to receive an issued binary DER certificate.

### 4. ACME Protocol Directory (`GET /.well-known/acme/directory`)
* Inspect the RFC 8555 directory entry points (`newNonce`, `newAccount`, `newOrder`, `revokeCert`).

### 5. Prometheus Observability (`GET /metrics`)
* Inspect real-time counters and gauges for issued certificates, OCSP requests, queue depth, and revocation totals.

---

## 📦 Generating Client SDKs

Because `go-certa` exports a standard OpenAPI 3.0 specification at `/swagger/doc.json`, you can generate client libraries in any language using [OpenAPI Generator](https://openapi-generator.tech/):

```bash
# Download the spec
curl -s http://localhost:8080/swagger/doc.json -o openapi.json

# Generate a Go client SDK
openapi-generator-cli generate -i openapi.json -g go -o ./clients/go

# Generate a Python client SDK
openapi-generator-cli generate -i openapi.json -g python -o ./clients/python
```
