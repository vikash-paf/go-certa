package ctlog_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"go-certa/pkg/ca"
	"go-certa/pkg/ctlog"
	"go-certa/pkg/signer"
)

func TestPreCertificateTemplate_PoisonExtension(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "precert.example.com"},
	}

	preCertTmpl, err := ctlog.BuildPreCertificateTemplate(tmpl)
	if err != nil {
		t.Fatalf("BuildPreCertificateTemplate failed: %v", err)
	}

	foundPoison := false
	for _, ext := range preCertTmpl.ExtraExtensions {
		if ext.Id.Equal(ctlog.OIDExtensionCTPoison) {
			foundPoison = true
			if !ext.Critical {
				t.Errorf("CT Poison extension must be marked critical")
			}
			if !bytes.Equal(ext.Value, []byte{0x05, 0x00}) {
				t.Errorf("expected ASN.1 NULL value, got %x", ext.Value)
			}
		}
	}

	if !foundPoison {
		t.Fatalf("CT Poison extension not found in pre-certificate template")
	}
}

func TestMockCTLog_AddPreChain(t *testing.T) {
	mockLog, err := ctlog.NewMockCTLogServer()
	if err != nil {
		t.Fatalf("NewMockCTLogServer failed: %v", err)
	}
	defer mockLog.Close()

	// Setup dummy issuer and precert
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CT Test CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	preCertDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	submitter := ctlog.NewCTSubmitter(mockLog.URL(), nil)
	sctBytes, err := submitter.SubmitPreCertificate(context.Background(), preCertDER, caDER)
	if err != nil {
		t.Fatalf("SubmitPreCertificate failed: %v", err)
	}

	if len(sctBytes) < 43 { // minimum length: 1+32+8+2
		t.Fatalf("sctBytes length %d is too short", len(sctBytes))
	}
	if sctBytes[0] != 0 {
		t.Errorf("expected version 0, got %d", sctBytes[0])
	}
	if !bytes.Equal(sctBytes[1:33], mockLog.LogID[:]) {
		t.Errorf("log ID mismatch in SCT")
	}
}

func TestSerializeSCTList_And_Embed(t *testing.T) {
	sct1 := []byte("dummy-sct-1-payload-data-here")
	sct2 := []byte("dummy-sct-2-payload-data-here")

	serializedList, err := ctlog.SerializeSCTList([][]byte{sct1, sct2})
	if err != nil {
		t.Fatalf("SerializeSCTList failed: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5001),
		Subject:      pkix.Name{CommonName: "embed.example.com"},
	}

	// First build pre-cert with poison
	preCertTmpl, _ := ctlog.BuildPreCertificateTemplate(tmpl)

	// Now embed SCT list
	ctlog.EmbedSCTList(preCertTmpl, serializedList)

	hasPoison := false
	hasSCTList := false
	for _, ext := range preCertTmpl.ExtraExtensions {
		if ext.Id.Equal(ctlog.OIDExtensionCTPoison) {
			hasPoison = true
		}
		if ext.Id.Equal(ctlog.OIDExtensionSCTList) {
			hasSCTList = true
			if ext.Critical {
				t.Errorf("SCT List extension must be non-critical")
			}
			if !bytes.Equal(ext.Value, serializedList) {
				t.Errorf("embedded SCT list mismatch")
			}
		}
	}

	if hasPoison {
		t.Errorf("CT Poison extension must be removed when embedding SCT list")
	}
	if !hasSCTList {
		t.Errorf("SCT List extension must be present")
	}
}

func TestEndToEnd_SignCertificateWithCT(t *testing.T) {
	// 1. Setup 2 Mock CT Log Servers
	log1, err := ctlog.NewMockCTLogServer()
	if err != nil {
		t.Fatal(err)
	}
	defer log1.Close()

	log2, err := ctlog.NewMockCTLogServer()
	if err != nil {
		t.Fatal(err)
	}
	defer log2.Close()

	submitters := []*ctlog.CTSubmitter{
		ctlog.NewCTSubmitter(log1.URL(), nil),
		ctlog.NewCTSubmitter(log2.URL(), nil),
	}

	// 2. Setup Authority
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hsm := signer.NewHSMSigner(intKey, 0)
	auth, err := ca.NewAuthority(hsm)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Create CSR for "ct-tls.domain.com"
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "ct-tls.domain.com"},
		DNSNames: []string{"ct-tls.domain.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, clientKey)
	if err != nil {
		t.Fatal(err)
	}

	serial := big.NewInt(888777)
	profile := ca.DefaultServerTLSProfile()
	extConfig := ca.ExtensionConfig{
		OCSPServerURLs: []string{"http://ocsp.domain.com"},
	}

	// 4. Sign certificate with CT embedding
	certDER, err := auth.SignCertificateWithCT(
		context.Background(),
		csrDER,
		serial,
		profile,
		extConfig,
		30*24*time.Hour,
		nil,
		submitters,
	)
	if err != nil {
		t.Fatalf("SignCertificateWithCT failed: %v", err)
	}

	// 5. Parse and inspect certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed parsing issued certificate: %v", err)
	}

	hasPoison := false
	hasSCTList := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ctlog.OIDExtensionCTPoison) {
			hasPoison = true
		}
		if ext.Id.Equal(ctlog.OIDExtensionSCTList) {
			hasSCTList = true
			if ext.Critical {
				t.Errorf("SCT list extension must be non-critical")
			}
		}
	}

	if hasPoison {
		t.Fatalf("final certificate contains critical CT poison extension")
	}
	if !hasSCTList {
		t.Fatalf("final certificate missing SCT list extension")
	}

	// 6. Verify trust chain
	roots := x509.NewCertPool()
	roots.AddCert(auth.RootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(auth.IntermediateCert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "ct-tls.domain.com",
	})
	if err != nil {
		t.Fatalf("certificate chain verification failed: %v", err)
	}
}
