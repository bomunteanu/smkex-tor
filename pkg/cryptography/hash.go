package cryptography

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

const NonceSize = 32

func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

func BindingHash(gx, nc, gy, ns []byte) []byte {
	h := sha256.New()
	h.Write(gx)
	h.Write(nc)
	h.Write(gy)
	h.Write(ns)
	return h.Sum(nil)
}

func VerifyBindingHash(gx, nc, gy, ns, receivedHash []byte) error {
	expected := BindingHash(gx, nc, gy, ns)

	if subtle.ConstantTimeCompare(expected, receivedHash) != 1 {
		return fmt.Errorf("binding hash verification failed: active attack detected — " +
			"path 1 DH values do not match path 2 commitment")
	}

	return nil
}
