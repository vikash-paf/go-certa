# go-certa

A certificate authority service implementing automated enrollment and real-time status verification protocols.

## Features

* **Hardware Security Layer**: Simulated HSM signer utilizing Go's standard library cryptographic interfaces.
* **Core CA Hierarchy**: Root CA and Intermediate CA separation to protect the master keys.
* **Enrollment Protocols**: EST (RFC 7030) and ACME HTTP-01 challenge validation engines.
* **Revocation Status**: Online Certificate Status Protocol (OCSP) responder for real-time validation checks.

## Usage

Follow these steps to run the server and enroll a test client.

### 1. Generate a Test Certificate Signing Request (CSR)
Generate a private key and a CSR using OpenSSL:
```bash
openssl req -new -newkey rsa:2048 -nodes -keyout private.key -out request.csr -subj "/CN=client.example.com"
```

### 2. Format the CSR for the EST Protocol
EST simple enroll expects the raw binary certificate request encoded in Base64:
```bash
openssl req -in request.csr -outform der | base64 > request.b64
```

### 3. Start the CA Server
Compile and start the service:
```bash
go run ./cmd/certa-server/
```
The server will boot and listen for connections on `http://localhost:8080`.

### 4. Fetch the CA Certificate Chain
Query the EST endpoint to retrieve the current Intermediate CA certificate:
```bash
curl http://localhost:8080/.well-known/est/cacerts --output cacert.pem
```

### 5. Enroll the Client
Submit the base64-encoded CSR to the enrollment endpoint to receive your client certificate:
```bash
curl -X POST -d @request.b64 --output client.der http://localhost:8080/.well-known/est/simpleenroll
```

### 6. Read the Issued Certificate
Parse the returned binary certificate to verify its attributes:
```bash
openssl x509 -in client.der -inform der -text -noout
```
