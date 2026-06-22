// crypto_helpers.go — key generation helpers for the service.
// This file is the scan target in the CI-gate example.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// NewSigningKey returns an RSA-3072 signing key.
func NewSigningKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 3072)
}

// NewECKey returns a P-256 ECDSA key used for short-lived session signatures.
func NewECKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
