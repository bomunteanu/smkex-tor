package cryptography

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

type KeyPair struct {
	privateKey *ecdh.PrivateKey

	// PublicKey - 32-byte X25519 public key that is safe to transmit
	PublicKey []byte
}

func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()

	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key pair: %w", err)
	}

	return &KeyPair{
		privateKey: priv,
		PublicKey:  priv.PublicKey().Bytes(),
	}, nil
}

func (kp *KeyPair) ComputeSharedSecret(peerPublicKey []byte) ([]byte, error) {
	curve := ecdh.X25519()

	peerPub, err := curve.NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer public key: %w", err)
	}

	secret, err := kp.privateKey.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH computation failed: %w", err)
	}

	return secret, nil
}
