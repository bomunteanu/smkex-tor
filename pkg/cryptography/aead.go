package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const GCMNonceSize = 12

func Encrypt(plaintext, key, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM wrapper: %w", err)
	}

	nonce := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate GCM nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, additionalData)

	return ciphertext, nil
}

func Decrypt(ciphertext, key, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM wrapper: %w", err)
	}

	minLen := GCMNonceSize + gcm.Overhead()
	if len(ciphertext) < minLen {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d (nonce + tag)",
			len(ciphertext), minLen)
	}

	nonce := ciphertext[:GCMNonceSize]
	ciphertext = ciphertext[GCMNonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM authentication failed (message tampered or wrong key): %w", err)
	}

	return plaintext, nil
}
