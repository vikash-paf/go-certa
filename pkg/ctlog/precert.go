package ctlog

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	// OIDExtensionCTPoison is the critical Certificate Transparency Poison extension (RFC 6962 §3.1).
	OIDExtensionCTPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

	// OIDExtensionSCTList is the non-critical SignedCertificateTimestampList extension (RFC 6962 §3.3).
	OIDExtensionSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// BuildPreCertificateTemplate constructs a clone of the certificate template containing the critical CT Poison extension.
func BuildPreCertificateTemplate(tmpl *x509.Certificate) (*x509.Certificate, error) {
	if tmpl == nil {
		return nil, errors.New("template cannot be nil")
	}

	preCertTmpl := *tmpl

	// Copy ExtraExtensions slice
	exts := make([]pkix.Extension, len(tmpl.ExtraExtensions))
	copy(exts, tmpl.ExtraExtensions)

	// Add critical CT Poison extension (ASN.1 NULL value: 0x05, 0x00)
	exts = append(exts, pkix.Extension{
		Id:       OIDExtensionCTPoison,
		Critical: true,
		Value:    []byte{0x05, 0x00},
	})

	preCertTmpl.ExtraExtensions = exts
	return &preCertTmpl, nil
}

// SerializeSCTList converts a slice of raw binary SCTs into the TLS-encoded SignedCertificateTimestampList,
// wrapped in an ASN.1 OCTET STRING per RFC 6962 §3.3.
func SerializeSCTList(scts [][]byte) ([]byte, error) {
	if len(scts) == 0 {
		return nil, errors.New("sct list cannot be empty")
	}

	var elements []byte
	for i, sct := range scts {
		sctLen := len(sct)
		if sctLen == 0 || sctLen > 65535 {
			return nil, fmt.Errorf("invalid SCT length %d at index %d", sctLen, i)
		}
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(sctLen))
		elements = append(elements, lenBytes...)
		elements = append(elements, sct...)
	}

	totalLen := len(elements)
	if totalLen > 65535 {
		return nil, fmt.Errorf("total SCT list length %d exceeds 65535", totalLen)
	}

	listLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(listLenBytes, uint16(totalLen))
	tlsEncodedList := append(listLenBytes, elements...)

	// Wrap in ASN.1 OCTET STRING
	return asn1.Marshal(tlsEncodedList)
}

// EmbedSCTList removes any CT Poison extension and injects the SignedCertificateTimestampList extension.
func EmbedSCTList(tmpl *x509.Certificate, serializedSCTList []byte) {
	if tmpl == nil || len(serializedSCTList) == 0 {
		return
	}

	var filteredExts []pkix.Extension
	for _, ext := range tmpl.ExtraExtensions {
		if !ext.Id.Equal(OIDExtensionCTPoison) {
			filteredExts = append(filteredExts, ext)
		}
	}

	// Add SCT list extension (RFC 6962 §3.3 requires non-critical)
	filteredExts = append(filteredExts, pkix.Extension{
		Id:       OIDExtensionSCTList,
		Critical: false,
		Value:    serializedSCTList,
	})

	tmpl.ExtraExtensions = filteredExts
}
