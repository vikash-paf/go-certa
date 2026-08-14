package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

func main() {
	// 1. Generate Root CA
	caKey, caCertDER := generateCA()
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		log.Fatalf("failed to parse CA certificate: %v", err)
	}

	// 2. Generate Server Certificate (signed by Root CA)
	serverKey, serverCertDER := generateCert(caCert, caKey, "localhost", true)

	// 3. Generate Client Certificate (signed by Root CA)
	clientKey, clientCertDER := generateCert(caCert, caKey, "test-client", false)

	// 4. Configure and Start the mTLS Server
	serverCert, err := tls.X509KeyPair(serverCertDER, serverKey)
	if err != nil {
		log.Fatalf("failed to load server key pair: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()
	serverAddr := listener.Addr().String()

	srv := &http.Server{
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.TLS.PeerCertificates) > 0 {
				clientCN := r.TLS.PeerCertificates[0].Subject.CommonName
				fmt.Fprintf(w, "Hello %s, mutual authentication successful!", clientCN)
				return
			}
			http.Error(w, "client certificate missing", http.StatusBadRequest)
		}),
	}

	tlsListener := tls.NewListener(listener, tlsConfig)
	go func() {
		if err := srv.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()
	defer srv.Close()

	// 5. Configure and Run the mTLS Client
	clientCert, err := tls.X509KeyPair(clientCertDER, clientKey)
	if err != nil {
		log.Fatalf("failed to load client key pair: %v", err)
	}

	clientTLSConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caPool,
		InsecureSkipVerify: false,
		ServerName:         "localhost",
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
	}

	resp, err := client.Get("https://" + serverAddr)
	if err != nil {
		log.Fatalf("client request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %v", err)
	}

	fmt.Printf("Server Response: %s\n", string(body))
}

func generateCA() (*rsa.PrivateKey, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Local mTLS Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("failed to create CA certificate: %v", err)
	}

	return key, der
}

func generateCert(parent *x509.Certificate, parentKey *rsa.PrivateKey, cn string, isServer bool) ([]byte, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	if isServer {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{cn}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		log.Fatalf("failed to create certificate: %v", err)
	}

	keyBlock := x509.MarshalPKCS1PrivateKey(key)

	// Helper to PEM encode the private key bytes
	pemKeyBytes := encodePEM("RSA PRIVATE KEY", keyBlock)
	pemCertBytes := encodePEM("CERTIFICATE", der)

	return pemKeyBytes, pemCertBytes
}

func encodePEM(pemType string, b []byte) []byte {
	block := fmt.Sprintf("-----BEGIN %s-----\n", pemType)
	base64Str := ""
	for i, c := range base64Encode(b) {
		base64Str += string(c)
		if (i+1)%64 == 0 {
			base64Str += "\n"
		}
	}
	if base64Str[len(base64Str)-1] != '\n' {
		base64Str += "\n"
	}
	block += base64Str
	block += fmt.Sprintf("-----END %s-----\n", pemType)
	return []byte(block)
}

func base64Encode(b []byte) string {
	const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	nb := len(b)
	buf := make([]byte, ((nb+2)/3)*4)
	di, si := 0, 0
	n := (nb / 3) * 3
	for si < n {
		val := uint32(b[si])<<16 | uint32(b[si+1])<<8 | uint32(b[si+2])
		buf[di] = encodeStd[val>>18&0x3F]
		buf[di+1] = encodeStd[val>>12&0x3F]
		buf[di+2] = encodeStd[val>>6&0x3F]
		buf[di+3] = encodeStd[val&0x3F]
		si += 3
		di += 4
	}
	remain := nb - si
	if remain == 1 {
		val := uint32(b[si]) << 16
		buf[di] = encodeStd[val>>18&0x3F]
		buf[di+1] = encodeStd[val>>12&0x3F]
		buf[di+2] = '='
		buf[di+3] = '='
	} else if remain == 2 {
		val := uint32(b[si])<<16 | uint32(b[si+1])<<8
		buf[di] = encodeStd[val>>18&0x3F]
		buf[di+1] = encodeStd[val>>12&0x3F]
		buf[di+2] = encodeStd[val>>6&0x3F]
		buf[di+3] = '='
	}
	return string(buf)
}
