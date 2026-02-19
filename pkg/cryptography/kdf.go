package cryptography

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const SessionKeySize = 32

func DeriveSessionKey(sharedSecret, clientNonce, serverNonce []byte) ([]byte, error) {
	salt := make([]byte, 0, len(clientNonce)+len(serverNonce))
	salt = append(salt, clientNonce...)
	salt = append(salt, serverNonce...)

	info := []byte("smkex-tor v1 session key")

	reader := hkdf.New(sha256.New, sharedSecret, salt, info)

	key := make([]byte, SessionKeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	return key, nil
}
