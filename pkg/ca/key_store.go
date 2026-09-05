package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"go-certa/pkg/signer"
)

// CAHierarchyFiles tracks the paths to persisted CA materials.
type CAHierarchyFiles struct {
	RootKeyPath         string
	RootCertPath        string
	IntermediateKeyPath string
	IntermediateCertPath string
}

// DefaultCAHierarchyFiles returns paths inside the specified directory.
func DefaultCAHierarchyFiles(dir string) CAHierarchyFiles {
	return CAHierarchyFiles{
		RootKeyPath:          filepath.Join(dir, "root.key"),
		RootCertPath:         filepath.Join(dir, "root.crt"),
		IntermediateKeyPath:  filepath.Join(dir, "intermediate.key"),
		IntermediateCertPath: filepath.Join(dir, "intermediate.crt"),
	}
}

// LoadOrInitializeAuthority loads existing CA keys and certificates from disk,
// or performs the initial cryptographic ceremony, saves them, and returns the authority.
func LoadOrInitializeAuthority(dataDir string, signerLatency time.Duration) (*Authority, *signer.HSMSigner, error) {
	caDir := filepath.Join(dataDir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("failed creating CA directory: %w", err)
	}

	paths := DefaultCAHierarchyFiles(caDir)

	// Check if all files exist
	if filesExist(paths.RootCertPath, paths.IntermediateCertPath, paths.IntermediateKeyPath) {
		return loadAuthority(paths, signerLatency)
	}

	// Otherwise, generate new hierarchy and persist
	return generateAndPersistAuthority(paths, signerLatency)
}

func filesExist(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

func loadAuthority(paths CAHierarchyFiles, signerLatency time.Duration) (*Authority, *signer.HSMSigner, error) {
	// 1. Read Root Cert
	rootDER, err := readPEMCertificate(paths.RootCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading root cert: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing root cert: %w", err)
	}

	// 2. Read Intermediate Cert
	intDER, err := readPEMCertificate(paths.IntermediateCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading intermediate cert: %w", err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing intermediate cert: %w", err)
	}

	// 3. Read Intermediate Private Key
	intKey, err := readPEMPrivateKey(paths.IntermediateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading intermediate key: %w", err)
	}

	hsmSigner := signer.NewHSMSigner(intKey, signerLatency)
	auth := &Authority{
		RootCert:         rootCert,
		IntermediateCert: intCert,
		Signer:           hsmSigner,
		Policy:           NewDefaultPolicyEngine(),
	}

	return auth, hsmSigner, nil
}

func generateAndPersistAuthority(paths CAHierarchyFiles, signerLatency time.Duration) (*Authority, *signer.HSMSigner, error) {
	// 1. Generate Root CA Key & Certificate
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating root key: %w", err)
	}

	rootSKID, err := ComputeSubjectKeyID(&rootKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed computing root key id: %w", err)
	}

	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Go-Certa Trust Network"},
			CommonName:   "Go-Certa Root CA G1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		SubjectKeyId:          rootSKID,
		AuthorityKeyId:        rootSKID,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating root certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing root certificate: %w", err)
	}

	// 2. Generate Intermediate CA Key & Certificate
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating intermediate key: %w", err)
	}

	intSKID, err := ComputeSubjectKeyID(&intKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed computing intermediate key id: %w", err)
	}

	intTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Go-Certa Trust Network"},
			CommonName:   "Go-Certa Issuing Intermediate CA 1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		SubjectKeyId:          intSKID,
		AuthorityKeyId:        rootSKID,
	}

	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating intermediate certificate: %w", err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing intermediate certificate: %w", err)
	}

	// 3. Save to disk with secure permissions
	if err := writePEMPrivateKey(paths.RootKeyPath, rootKey); err != nil {
		return nil, nil, fmt.Errorf("failed writing root key: %w", err)
	}
	if err := writePEMCertificate(paths.RootCertPath, rootDER); err != nil {
		return nil, nil, fmt.Errorf("failed writing root certificate: %w", err)
	}
	if err := writePEMPrivateKey(paths.IntermediateKeyPath, intKey); err != nil {
		return nil, nil, fmt.Errorf("failed writing intermediate key: %w", err)
	}
	if err := writePEMCertificate(paths.IntermediateCertPath, intDER); err != nil {
		return nil, nil, fmt.Errorf("failed writing intermediate certificate: %w", err)
	}

	hsmSigner := signer.NewHSMSigner(intKey, signerLatency)
	auth := &Authority{
		RootCert:         rootCert,
		IntermediateCert: intCert,
		Signer:           hsmSigner,
		Policy:           NewDefaultPolicyEngine(),
	}

	return auth, hsmSigner, nil
}

func writePEMPrivateKey(path string, key *rsa.PrivateKey) error {
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func writePEMCertificate(path string, certDER []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

func readPEMCertificate(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate block in %s", path)
	}
	return block.Bytes, nil
}

func readPEMPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM private key block in %s", path)
	}

	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not an RSA private key", path)
	}
	return rsaKey, nil
}
