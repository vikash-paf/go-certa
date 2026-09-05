package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

var (
	// ErrInvalidJWS indicates the JWS structure or base64 decoding failed.
	ErrInvalidJWS = errors.New("invalid JWS payload")

	// ErrUnsupportedJWSAlgorithm indicates the algorithm is not supported (only RS256 and ES256 allowed).
	ErrUnsupportedJWSAlgorithm = errors.New("unsupported JWS algorithm")

	// ErrInvalidSignature indicates signature verification failed.
	ErrInvalidSignature = errors.New("JWS signature verification failed")

	// ErrMissingKey indicates neither jwk nor kid was supplied.
	ErrMissingKey = errors.New("missing public key or kid in JWS header")
)

// JWK represents an RFC 7517 JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWSHeader represents the protected header of an RFC 8555 JWS object.
type JWSHeader struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce,omitempty"`
	URL   string `json:"url,omitempty"`
	JWK   *JWK   `json:"jwk,omitempty"`
	Kid   string `json:"kid,omitempty"`
}

// JWSMessage represents the serialized JWS JSON object.
type JWSMessage struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// KeyToJWK converts a crypto.PublicKey into an RFC 7517 JWK.
func KeyToJWK(pub crypto.PublicKey) (*JWK, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return &JWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: only P-256 supported for EC keys", ErrUnsupportedJWSAlgorithm)
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()
		// Pad to coordinate byte length
		xPadded := make([]byte, byteLen)
		yPadded := make([]byte, byteLen)
		copy(xPadded[byteLen-len(xBytes):], xBytes)
		copy(yPadded[byteLen-len(yBytes):], yBytes)

		return &JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(xPadded),
			Y:   base64.RawURLEncoding.EncodeToString(yPadded),
		}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported key type %T", ErrUnsupportedJWSAlgorithm, pub)
	}
}

// JWKToKey parses an RFC 7517 JWK into a crypto.PublicKey.
func JWKToKey(jwk *JWK) (crypto.PublicKey, error) {
	if jwk == nil {
		return nil, errors.New("nil JWK")
	}

	switch jwk.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA modulus N: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA exponent E: %w", err)
		}
		n := new(big.Int).SetBytes(nBytes)
		eInt := new(big.Int).SetBytes(eBytes).Int64()
		return &rsa.PublicKey{N: n, E: int(eInt)}, nil

	case "EC":
		if jwk.Crv != "P-256" {
			return nil, fmt.Errorf("%w: unsupported curve %q", ErrUnsupportedJWSAlgorithm, jwk.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("invalid EC coordinate X: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("invalid EC coordinate Y: %w", err)
		}
		curve := elliptic.P256()
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("EC point is not on P-256 curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	default:
		return nil, fmt.Errorf("%w: unknown kty %q", ErrUnsupportedJWSAlgorithm, jwk.Kty)
	}
}

// ComputeJWKThumbprint calculates the RFC 7638 SHA-256 thumbprint in Base64URL encoding.
func ComputeJWKThumbprint(pub crypto.PublicKey) (string, error) {
	jwk, err := KeyToJWK(pub)
	if err != nil {
		return "", err
	}

	var canonicalJSON string
	switch jwk.Kty {
	case "RSA":
		// Canonical JSON keys in alphabetical order: e, kty, n
		canonicalJSON = fmt.Sprintf(`{"e":%q,"kty":%q,"n":%q}`, jwk.E, jwk.Kty, jwk.N)
	case "EC":
		// Canonical JSON keys in alphabetical order: crv, kty, x, y
		canonicalJSON = fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk.Crv, jwk.Kty, jwk.X, jwk.Y)
	default:
		return "", fmt.Errorf("%w: kty %q", ErrUnsupportedJWSAlgorithm, jwk.Kty)
	}

	hash := sha256.Sum256([]byte(canonicalJSON))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// KeyLookupFunc retrieves a public key by key ID (Account URL).
type KeyLookupFunc func(kid string) (crypto.PublicKey, error)

// ParsedJWS contains the decoded and verified JWS message details.
type ParsedJWS struct {
	Header    JWSHeader
	Payload   []byte
	PublicKey crypto.PublicKey
}

// DecodeAndVerifyJWS decodes and validates the signature of an incoming JWS message.
func DecodeAndVerifyJWS(body []byte, keyLookup KeyLookupFunc) (*ParsedJWS, error) {
	var msg JWSMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJWS, err)
	}

	if msg.Protected == "" || msg.Signature == "" {
		return nil, fmt.Errorf("%w: missing protected or signature", ErrInvalidJWS)
	}

	// 1. Decode Protected Header
	headerBytes, err := base64.RawURLEncoding.DecodeString(msg.Protected)
	if err != nil {
		return nil, fmt.Errorf("%w: failed decoding protected header: %v", ErrInvalidJWS, err)
	}

	var header JWSHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: failed parsing protected header JSON: %v", ErrInvalidJWS, err)
	}

	// 2. Decode Payload (can be empty string for POST-as-GET)
	var payloadBytes []byte
	if msg.Payload != "" {
		payloadBytes, err = base64.RawURLEncoding.DecodeString(msg.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: failed decoding payload: %v", ErrInvalidJWS, err)
		}
	}

	// 3. Resolve Public Key
	var pubKey crypto.PublicKey
	if header.JWK != nil {
		pubKey, err = JWKToKey(header.JWK)
		if err != nil {
			return nil, err
		}
	} else if header.Kid != "" {
		if keyLookup == nil {
			return nil, errors.New("keyLookup function not provided for kid lookup")
		}
		pubKey, err = keyLookup(header.Kid)
		if err != nil {
			return nil, fmt.Errorf("failed resolving key for kid %q: %w", header.Kid, err)
		}
	} else {
		return nil, ErrMissingKey
	}

	// 4. Verify Signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(msg.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: failed decoding signature: %v", ErrInvalidJWS, err)
	}

	signingInput := []byte(msg.Protected + "." + msg.Payload)
	hash := sha256.Sum256(signingInput)

	switch header.Alg {
	case "RS256":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected RSA public key for RS256", ErrInvalidSignature)
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sigBytes); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}

	case "ES256":
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: expected ECDSA public key for ES256", ErrInvalidSignature)
		}
		if len(sigBytes) != 64 {
			return nil, fmt.Errorf("%w: ES256 signature must be 64 bytes (R||S)", ErrInvalidSignature)
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if !ecdsa.Verify(ecPub, hash[:], r, s) {
			return nil, ErrInvalidSignature
		}

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedJWSAlgorithm, header.Alg)
	}

	return &ParsedJWS{
		Header:    header,
		Payload:   payloadBytes,
		PublicKey: pubKey,
	}, nil
}

// SignJWS is a helper that constructs and signs an RFC 8555 JWS JSON payload.
func SignJWS(signer crypto.Signer, header JWSHeader, payload []byte) ([]byte, error) {
	var alg string
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		alg = "RS256"
	case *ecdsa.PublicKey:
		alg = "ES256"
	default:
		return nil, fmt.Errorf("%w: unsupported signer %T", ErrUnsupportedJWSAlgorithm, signer.Public())
	}
	header.Alg = alg

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}

	protB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	var payB64 string
	if len(payload) > 0 {
		payB64 = base64.RawURLEncoding.EncodeToString(payload)
	}

	signingInput := []byte(protB64 + "." + payB64)
	hash := sha256.Sum256(signingInput)

	var rawSig []byte
	switch s := signer.(type) {
	case *rsa.PrivateKey:
		rawSig, err = rsa.SignPKCS1v15(rand.Reader, s, crypto.SHA256, hash[:])
		if err != nil {
			return nil, err
		}
	case *ecdsa.PrivateKey:
		r, sInt, err := ecdsa.Sign(rand.Reader, s, hash[:])
		if err != nil {
			return nil, err
		}
		rBytes := r.Bytes()
		sBytes := sInt.Bytes()
		rawSig = make([]byte, 64)
		copy(rawSig[32-len(rBytes):32], rBytes)
		copy(rawSig[64-len(sBytes):64], sBytes)
	default:
		return nil, fmt.Errorf("unsupported signer key type: %T", signer)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(rawSig)
	msg := JWSMessage{
		Protected: protB64,
		Payload:   payB64,
		Signature: sigB64,
	}

	return json.Marshal(msg)
}
