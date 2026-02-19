package cryptography

import (
	"bytes"
	"testing"
)

// ────────────────────────────────────────────────────────────────────────────
// ECDH tests
// ────────────────────────────────────────────────────────────────────────────

// TestGenerateKeyPair verifies that key generation produces a non-nil key pair
// with a 32-byte public key (the fixed size for X25519).
func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	if kp == nil {
		t.Fatal("GenerateKeyPair() returned nil KeyPair")
	}
	if len(kp.PublicKey) != 32 {
		t.Fatalf("expected public key length 32, got %d", len(kp.PublicKey))
	}
}

// TestGenerateKeyPairIsRandom verifies that two independently generated key
// pairs have different public keys. A collision here would indicate a broken
// random number generator.
func TestGenerateKeyPairIsRandom(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("first GenerateKeyPair() error: %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("second GenerateKeyPair() error: %v", err)
	}
	if bytes.Equal(kp1.PublicKey, kp2.PublicKey) {
		t.Fatal("two independently generated key pairs produced identical public keys")
	}
}

// TestSharedSecretAgreement is the core DH correctness test: client and server
// must derive the same shared secret from each other's public keys.
//
//	client: sharedSecret = ECDH(clientPriv, serverPub) = g^(xy)
//	server: sharedSecret = ECDH(serverPriv, clientPub) = g^(yx) = g^(xy)
func TestSharedSecretAgreement(t *testing.T) {
	clientKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("client GenerateKeyPair() error: %v", err)
	}
	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server GenerateKeyPair() error: %v", err)
	}

	clientSecret, err := clientKP.ComputeSharedSecret(serverKP.PublicKey)
	if err != nil {
		t.Fatalf("client ComputeSharedSecret() error: %v", err)
	}

	serverSecret, err := serverKP.ComputeSharedSecret(clientKP.PublicKey)
	if err != nil {
		t.Fatalf("server ComputeSharedSecret() error: %v", err)
	}

	if !bytes.Equal(clientSecret, serverSecret) {
		t.Fatalf("shared secrets do not match:\n  client: %x\n  server: %x",
			clientSecret, serverSecret)
	}
}

// TestSharedSecretLength verifies that the ECDH output is 32 bytes,
// as expected for X25519.
func TestSharedSecretLength(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	secret, err := kp1.ComputeSharedSecret(kp2.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret() error: %v", err)
	}
	if len(secret) != 32 {
		t.Fatalf("expected shared secret length 32, got %d", len(secret))
	}
}

// TestSharedSecretDiffersAcrossSessions verifies that two independent DH
// exchanges produce different shared secrets, i.e. sessions are independent.
func TestSharedSecretDiffersAcrossSessions(t *testing.T) {
	a1, _ := GenerateKeyPair()
	b1, _ := GenerateKeyPair()
	a2, _ := GenerateKeyPair()
	b2, _ := GenerateKeyPair()

	secret1, _ := a1.ComputeSharedSecret(b1.PublicKey)
	secret2, _ := a2.ComputeSharedSecret(b2.PublicKey)

	if bytes.Equal(secret1, secret2) {
		t.Fatal("two independent DH sessions produced the same shared secret")
	}
}

// TestComputeSharedSecretInvalidKey verifies that an invalid peer public key
// (wrong length) is rejected with an error.
func TestComputeSharedSecretInvalidKey(t *testing.T) {
	kp, _ := GenerateKeyPair()

	_, err := kp.ComputeSharedSecret([]byte("too short"))
	if err == nil {
		t.Fatal("expected error for invalid peer public key, got nil")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// KDF tests
// ────────────────────────────────────────────────────────────────────────────

// TestDeriveSessionKeyLength verifies that the derived key is exactly
// SessionKeySize bytes (32 bytes = 256 bits for AES-256).
func TestDeriveSessionKeyLength(t *testing.T) {
	secret := make([]byte, 32)
	nc := make([]byte, NonceSize)
	ns := make([]byte, NonceSize)

	key, err := DeriveSessionKey(secret, nc, ns)
	if err != nil {
		t.Fatalf("DeriveSessionKey() error: %v", err)
	}
	if len(key) != SessionKeySize {
		t.Fatalf("expected key length %d, got %d", SessionKeySize, len(key))
	}
}

// TestDeriveSessionKeyDeterministic verifies that the same inputs always
// produce the same output — HKDF is a deterministic function.
func TestDeriveSessionKeyDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	nc := bytes.Repeat([]byte{0xCD}, NonceSize)
	ns := bytes.Repeat([]byte{0xEF}, NonceSize)

	key1, err := DeriveSessionKey(secret, nc, ns)
	if err != nil {
		t.Fatalf("first DeriveSessionKey() error: %v", err)
	}
	key2, err := DeriveSessionKey(secret, nc, ns)
	if err != nil {
		t.Fatalf("second DeriveSessionKey() error: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("DeriveSessionKey is not deterministic: same inputs produced different outputs")
	}
}

// TestDeriveSessionKeySensitiveToSecret verifies that a different shared
// secret produces a completely different session key.
func TestDeriveSessionKeySensitiveToSecret(t *testing.T) {
	nc := bytes.Repeat([]byte{0x01}, NonceSize)
	ns := bytes.Repeat([]byte{0x02}, NonceSize)

	secret1 := bytes.Repeat([]byte{0xAA}, 32)
	secret2 := bytes.Repeat([]byte{0xBB}, 32)

	key1, _ := DeriveSessionKey(secret1, nc, ns)
	key2, _ := DeriveSessionKey(secret2, nc, ns)

	if bytes.Equal(key1, key2) {
		t.Fatal("different shared secrets produced the same session key")
	}
}

// TestDeriveSessionKeySensitiveToClientNonce verifies that a different NC
// produces a completely different session key. This ensures per-session
// freshness: even if the same DH keys are reused, different nonces produce
// different session keys.
func TestDeriveSessionKeySensitiveToClientNonce(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	ns := bytes.Repeat([]byte{0x02}, NonceSize)

	nc1 := bytes.Repeat([]byte{0x01}, NonceSize)
	nc2 := bytes.Repeat([]byte{0x99}, NonceSize)

	key1, _ := DeriveSessionKey(secret, nc1, ns)
	key2, _ := DeriveSessionKey(secret, nc2, ns)

	if bytes.Equal(key1, key2) {
		t.Fatal("different client nonces produced the same session key")
	}
}

// TestDeriveSessionKeySensitiveToServerNonce verifies the same freshness
// property for NS.
func TestDeriveSessionKeySensitiveToServerNonce(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	nc := bytes.Repeat([]byte{0x01}, NonceSize)

	ns1 := bytes.Repeat([]byte{0x02}, NonceSize)
	ns2 := bytes.Repeat([]byte{0x88}, NonceSize)

	key1, _ := DeriveSessionKey(secret, nc, ns1)
	key2, _ := DeriveSessionKey(secret, nc, ns2)

	if bytes.Equal(key1, key2) {
		t.Fatal("different server nonces produced the same session key")
	}
}

// TestDeriveSessionKeyEndToEnd simulates a full SMKEX key derivation:
// both parties perform ECDH and then run HKDF, verifying they reach the
// same session key.
func TestDeriveSessionKeyEndToEnd(t *testing.T) {
	clientKP, _ := GenerateKeyPair()
	serverKP, _ := GenerateKeyPair()

	nc, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() NC error: %v", err)
	}
	ns, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() NS error: %v", err)
	}

	clientRawSecret, _ := clientKP.ComputeSharedSecret(serverKP.PublicKey)
	serverRawSecret, _ := serverKP.ComputeSharedSecret(clientKP.PublicKey)

	clientKey, err := DeriveSessionKey(clientRawSecret, nc, ns)
	if err != nil {
		t.Fatalf("client DeriveSessionKey() error: %v", err)
	}
	serverKey, err := DeriveSessionKey(serverRawSecret, nc, ns)
	if err != nil {
		t.Fatalf("server DeriveSessionKey() error: %v", err)
	}

	if !bytes.Equal(clientKey, serverKey) {
		t.Fatalf("client and server derived different session keys:\n  client: %x\n  server: %x",
			clientKey, serverKey)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Nonce and binding hash tests
// ────────────────────────────────────────────────────────────────────────────

// TestGenerateNonceLength verifies that generated nonces are exactly NonceSize
// bytes.
func TestGenerateNonceLength(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error: %v", err)
	}
	if len(nonce) != NonceSize {
		t.Fatalf("expected nonce length %d, got %d", NonceSize, len(nonce))
	}
}

// TestGenerateNonceIsRandom verifies that two generated nonces are different.
func TestGenerateNonceIsRandom(t *testing.T) {
	n1, _ := GenerateNonce()
	n2, _ := GenerateNonce()
	if bytes.Equal(n1, n2) {
		t.Fatal("two independently generated nonces are identical")
	}
}

// TestBindingHashLength verifies that the binding hash output is 32 bytes
// (SHA-256 output), matching λ in the paper's security bound st/2^λ.
func TestBindingHashLength(t *testing.T) {
	gx := make([]byte, 32)
	nc := make([]byte, NonceSize)
	gy := make([]byte, 32)
	ns := make([]byte, NonceSize)

	h := BindingHash(gx, nc, gy, ns)
	if len(h) != 32 {
		t.Fatalf("expected binding hash length 32, got %d", len(h))
	}
}

// TestBindingHashDeterministic verifies that the same inputs always produce
// the same hash — SHA-256 is deterministic.
func TestBindingHashDeterministic(t *testing.T) {
	gx := bytes.Repeat([]byte{0x11}, 32)
	nc := bytes.Repeat([]byte{0x22}, NonceSize)
	gy := bytes.Repeat([]byte{0x33}, 32)
	ns := bytes.Repeat([]byte{0x44}, NonceSize)

	h1 := BindingHash(gx, nc, gy, ns)
	h2 := BindingHash(gx, nc, gy, ns)

	if !bytes.Equal(h1, h2) {
		t.Fatal("BindingHash is not deterministic")
	}
}

// TestBindingHashSensitiveToEachInput verifies that changing any single input
// changes the hash output. This is the avalanche property of SHA-256 and is
// what guarantees an active attacker cannot tamper with any single field
// without being detected.
func TestBindingHashSensitiveToEachInput(t *testing.T) {
	gx := bytes.Repeat([]byte{0x11}, 32)
	nc := bytes.Repeat([]byte{0x22}, NonceSize)
	gy := bytes.Repeat([]byte{0x33}, 32)
	ns := bytes.Repeat([]byte{0x44}, NonceSize)

	base := BindingHash(gx, nc, gy, ns)

	tampered := func(field string, modified []byte) {
		t.Helper()
		var h []byte
		switch field {
		case "gx":
			h = BindingHash(modified, nc, gy, ns)
		case "nc":
			h = BindingHash(gx, modified, gy, ns)
		case "gy":
			h = BindingHash(gx, nc, modified, ns)
		case "ns":
			h = BindingHash(gx, nc, gy, modified)
		}
		if bytes.Equal(base, h) {
			t.Errorf("modifying %s did not change the binding hash", field)
		}
	}

	tampered("gx", bytes.Repeat([]byte{0xFF}, 32))
	tampered("nc", bytes.Repeat([]byte{0xFF}, NonceSize))
	tampered("gy", bytes.Repeat([]byte{0xFF}, 32))
	tampered("ns", bytes.Repeat([]byte{0xFF}, NonceSize))
}

// TestVerifyBindingHashValid verifies that a correctly computed hash passes
// verification.
func TestVerifyBindingHashValid(t *testing.T) {
	gx := bytes.Repeat([]byte{0x11}, 32)
	nc := bytes.Repeat([]byte{0x22}, NonceSize)
	gy := bytes.Repeat([]byte{0x33}, 32)
	ns := bytes.Repeat([]byte{0x44}, NonceSize)

	h := BindingHash(gx, nc, gy, ns)

	if err := VerifyBindingHash(gx, nc, gy, ns, h); err != nil {
		t.Fatalf("VerifyBindingHash() failed for a valid hash: %v", err)
	}
}

// TestVerifyBindingHashDetectsTamperedGx simulates an active attacker on
// path 1 replacing the client's public key g^x. The client recomputes the
// hash with its original g^x and detects the mismatch.
func TestVerifyBindingHashDetectsTamperedGx(t *testing.T) {
	gx := bytes.Repeat([]byte{0x11}, 32)
	nc := bytes.Repeat([]byte{0x22}, NonceSize)
	gy := bytes.Repeat([]byte{0x33}, 32)
	ns := bytes.Repeat([]byte{0x44}, NonceSize)

	// Attacker replaces gx with gx' when forwarding to server;
	// server computes hash over gx', which client cannot verify with gx.
	gxPrime := bytes.Repeat([]byte{0xAA}, 32)
	attackerHash := BindingHash(gxPrime, nc, gy, ns)

	err := VerifyBindingHash(gx, nc, gy, ns, attackerHash)
	if err == nil {
		t.Fatal("VerifyBindingHash should have detected a tampered g^x but did not")
	}
}

// TestVerifyBindingHashDetectsTamperedGy simulates an active attacker on
// path 1 replacing the server's public key g^y.
func TestVerifyBindingHashDetectsTamperedGy(t *testing.T) {
	gx := bytes.Repeat([]byte{0x11}, 32)
	nc := bytes.Repeat([]byte{0x22}, NonceSize)
	gy := bytes.Repeat([]byte{0x33}, 32)
	ns := bytes.Repeat([]byte{0x44}, NonceSize)

	gyPrime := bytes.Repeat([]byte{0xBB}, 32)
	attackerHash := BindingHash(gx, nc, gyPrime, ns)

	err := VerifyBindingHash(gx, nc, gy, ns, attackerHash)
	if err == nil {
		t.Fatal("VerifyBindingHash should have detected a tampered g^y but did not")
	}
}

// TestVerifyBindingHashDetectsCorruptHash simulates an attacker on path 2
// replacing the hash itself with a random value.
func TestVerifyBindingHashDetectsCorruptHash(t *testing.T) {
	gx := bytes.Repeat([]byte{0x11}, 32)
	nc := bytes.Repeat([]byte{0x22}, NonceSize)
	gy := bytes.Repeat([]byte{0x33}, 32)
	ns := bytes.Repeat([]byte{0x44}, NonceSize)

	corruptHash := bytes.Repeat([]byte{0x00}, 32)

	err := VerifyBindingHash(gx, nc, gy, ns, corruptHash)
	if err == nil {
		t.Fatal("VerifyBindingHash should have detected a corrupted hash but did not")
	}
}

// TestVerifyBindingHashWrongLength verifies that a hash of incorrect length
// is always rejected.
func TestVerifyBindingHashWrongLength(t *testing.T) {
	gx := bytes.Repeat([]byte{0x11}, 32)
	nc := bytes.Repeat([]byte{0x22}, NonceSize)
	gy := bytes.Repeat([]byte{0x33}, 32)
	ns := bytes.Repeat([]byte{0x44}, NonceSize)

	shortHash := []byte{0xDE, 0xAD}

	err := VerifyBindingHash(gx, nc, gy, ns, shortHash)
	if err == nil {
		t.Fatal("VerifyBindingHash should have rejected a hash of wrong length but did not")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// AES-GCM tests
// ────────────────────────────────────────────────────────────────────────────

// newTestKey returns a 32-byte all-zero AES-256 key for testing.
func newTestKey() []byte {
	return make([]byte, 32)
}

// TestEncryptDecryptRoundTrip verifies basic encrypt-then-decrypt correctness.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := newTestKey()
	plaintext := []byte("Hello, SMKEX-Tor!")

	ciphertext, err := Encrypt(plaintext, key, nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	recovered, err := Decrypt(ciphertext, key, nil)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("round-trip failed:\n  original:  %q\n  recovered: %q", plaintext, recovered)
	}
}

// TestEncryptProducesRandomOutput verifies that encrypting the same plaintext
// twice with the same key produces different ciphertexts. This is the
// IND-CPA (semantic security) property: a random per-message nonce ensures
// that repeated encryptions are unlinkable.
func TestEncryptProducesRandomOutput(t *testing.T) {
	key := newTestKey()
	plaintext := []byte("same message every time")

	ct1, _ := Encrypt(plaintext, key, nil)
	ct2, _ := Encrypt(plaintext, key, nil)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of the same plaintext produced identical ciphertexts (nonce reuse?)")
	}
}

// TestDecryptFailsOnBitFlip verifies INT-CTXT: flipping any bit in the
// ciphertext body (after the nonce) causes authentication to fail. This is
// the fundamental advantage of GCM over CFB — tampering is always detected.
func TestDecryptFailsOnBitFlip(t *testing.T) {
	key := newTestKey()
	plaintext := []byte("integrity-protected message")

	ciphertext, _ := Encrypt(plaintext, key, nil)

	// Flip a bit in the ciphertext body (past the nonce).
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[GCMNonceSize] ^= 0x01

	_, err := Decrypt(tampered, key, nil)
	if err == nil {
		t.Fatal("Decrypt should have rejected a bit-flipped ciphertext but succeeded")
	}
}

// TestDecryptFailsOnTagTampering verifies that flipping a bit in the GCM
// authentication tag (the last 16 bytes) is also detected.
func TestDecryptFailsOnTagTampering(t *testing.T) {
	key := newTestKey()
	plaintext := []byte("tag must be intact")

	ciphertext, _ := Encrypt(plaintext, key, nil)

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF // flip last byte of the tag

	_, err := Decrypt(tampered, key, nil)
	if err == nil {
		t.Fatal("Decrypt should have rejected a tampered GCM tag but succeeded")
	}
}

// TestDecryptFailsWithWrongKey verifies that decryption with a different key
// fails authentication — the tag was computed under the original key.
func TestDecryptFailsWithWrongKey(t *testing.T) {
	key := newTestKey()
	plaintext := []byte("wrong key test")

	ciphertext, _ := Encrypt(plaintext, key, nil)

	wrongKey := bytes.Repeat([]byte{0xFF}, 32)
	_, err := Decrypt(ciphertext, wrongKey, nil)
	if err == nil {
		t.Fatal("Decrypt should have failed with a wrong key but succeeded")
	}
}

// TestEncryptDecryptWithAdditionalData verifies that authenticated additional
// data (AAD) is correctly enforced: the same AAD must be presented to
// Decrypt, otherwise authentication fails.
func TestEncryptDecryptWithAdditionalData(t *testing.T) {
	key := newTestKey()
	plaintext := []byte("message with AAD")
	aad := []byte("session-id:abc123 seq:1")

	ciphertext, err := Encrypt(plaintext, key, aad)
	if err != nil {
		t.Fatalf("Encrypt() with AAD error: %v", err)
	}

	// Correct AAD must succeed.
	recovered, err := Decrypt(ciphertext, key, aad)
	if err != nil {
		t.Fatalf("Decrypt() with correct AAD error: %v", err)
	}
	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("AAD round-trip failed: got %q, want %q", recovered, plaintext)
	}

	// Wrong AAD must fail — the attacker cannot modify the associated data
	// (e.g. the sequence number) without being detected.
	wrongAAD := []byte("session-id:abc123 seq:2")
	_, err = Decrypt(ciphertext, key, wrongAAD)
	if err == nil {
		t.Fatal("Decrypt should have failed with wrong AAD but succeeded")
	}
}

// TestDecryptFailsOnTruncatedCiphertext verifies that ciphertexts that are
// too short to contain even a nonce and tag are rejected before any
// decryption attempt.
func TestDecryptFailsOnTruncatedCiphertext(t *testing.T) {
	key := newTestKey()

	_, err := Decrypt([]byte("short"), key, nil)
	if err == nil {
		t.Fatal("Decrypt should have rejected a truncated ciphertext but succeeded")
	}
}

// TestEncryptDecryptEmptyPlaintext verifies that encrypting an empty message
// is handled correctly. The output must still contain the nonce and tag.
func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	key := newTestKey()
	plaintext := []byte{}

	ciphertext, err := Encrypt(plaintext, key, nil)
	if err != nil {
		t.Fatalf("Encrypt() empty plaintext error: %v", err)
	}

	// Minimum expected length: nonce (12) + tag (16) = 28 bytes.
	minExpected := GCMNonceSize + 16
	if len(ciphertext) < minExpected {
		t.Fatalf("encrypted empty plaintext too short: got %d bytes, want >= %d",
			len(ciphertext), minExpected)
	}

	recovered, err := Decrypt(ciphertext, key, nil)
	if err != nil {
		t.Fatalf("Decrypt() empty plaintext error: %v", err)
	}
	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("empty plaintext round-trip failed: got %q", recovered)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Full SMKEX handshake simulation
// ────────────────────────────────────────────────────────────────────────────

// TestFullSMKEXHandshake simulates the complete 4-message SMKEX key exchange
// and subsequent encrypted communication in a single process, verifying that:
//
//  1. Both parties derive the same session key.
//  2. The binding hash correctly ties path 1 values to path 2 nonces.
//  3. The derived session key can be used to encrypt and decrypt a message.
//
// Protocol recap (from the paper):
//
//	Path 1: A→B: g^x        B→A: g^y
//	Path 2: A→B: NC         B→A: NS || H(g^x, NC, g^y, NS)
func TestFullSMKEXHandshake(t *testing.T) {
	// ── Client generates ephemeral key pair and nonce ──────────────────────
	clientKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("client GenerateKeyPair() error: %v", err)
	}
	nc, err := GenerateNonce()
	if err != nil {
		t.Fatalf("client GenerateNonce() error: %v", err)
	}

	// ── Server receives g^x and NC; generates its own key pair and nonce ──
	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server GenerateKeyPair() error: %v", err)
	}
	ns, err := GenerateNonce()
	if err != nil {
		t.Fatalf("server GenerateNonce() error: %v", err)
	}

	// ── Server computes and sends binding hash over path 2 ────────────────
	serverHash := BindingHash(clientKP.PublicKey, nc, serverKP.PublicKey, ns)

	// ── Client verifies the binding hash ──────────────────────────────────
	if err := VerifyBindingHash(clientKP.PublicKey, nc, serverKP.PublicKey, ns, serverHash); err != nil {
		t.Fatalf("client binding hash verification failed: %v", err)
	}

	// ── Both parties derive the session key ───────────────────────────────
	clientRaw, err := clientKP.ComputeSharedSecret(serverKP.PublicKey)
	if err != nil {
		t.Fatalf("client ComputeSharedSecret() error: %v", err)
	}
	serverRaw, err := serverKP.ComputeSharedSecret(clientKP.PublicKey)
	if err != nil {
		t.Fatalf("server ComputeSharedSecret() error: %v", err)
	}

	clientSessionKey, err := DeriveSessionKey(clientRaw, nc, ns)
	if err != nil {
		t.Fatalf("client DeriveSessionKey() error: %v", err)
	}
	serverSessionKey, err := DeriveSessionKey(serverRaw, nc, ns)
	if err != nil {
		t.Fatalf("server DeriveSessionKey() error: %v", err)
	}

	if !bytes.Equal(clientSessionKey, serverSessionKey) {
		t.Fatalf("session keys do not match after handshake:\n  client: %x\n  server: %x",
			clientSessionKey, serverSessionKey)
	}

	// ── Client encrypts a message; server decrypts it ─────────────────────
	message := []byte("secure message after SMKEX handshake")

	ciphertext, err := Encrypt(message, clientSessionKey, nil)
	if err != nil {
		t.Fatalf("Encrypt() post-handshake error: %v", err)
	}

	recovered, err := Decrypt(ciphertext, serverSessionKey, nil)
	if err != nil {
		t.Fatalf("Decrypt() post-handshake error: %v", err)
	}

	if !bytes.Equal(message, recovered) {
		t.Fatalf("post-handshake message mismatch:\n  sent:      %q\n  recovered: %q",
			message, recovered)
	}
}

// TestSMKEXHandshakeDetectsActiveAttackOnPath1 simulates an A/A attack where
// an attacker on path 1 replaces g^x with a forged g^x'. The server computes
// H(gx', NC, gy, NS) and sends it back. When the client verifies with its
// original g^x, the hash mismatch exposes the attack.
func TestSMKEXHandshakeDetectsActiveAttackOnPath1(t *testing.T) {
	// Client generates its real key pair and nonce.
	clientKP, _ := GenerateKeyPair()
	nc, _ := GenerateNonce()

	// Attacker generates a forged key pair to substitute for the client's.
	attackerKP, _ := GenerateKeyPair()

	// Server generates its key pair and nonce.
	serverKP, _ := GenerateKeyPair()
	ns, _ := GenerateNonce()

	// Server receives the attacker's forged g^x' (not the real g^x) on path 1,
	// and NC on path 2. It computes the hash over the forged value.
	serverHash := BindingHash(attackerKP.PublicKey, nc, serverKP.PublicKey, ns)

	// Client verifies the hash using its real g^x — mismatch must be detected.
	err := VerifyBindingHash(clientKP.PublicKey, nc, serverKP.PublicKey, ns, serverHash)
	if err == nil {
		t.Fatal("VerifyBindingHash should have detected the active attack on path 1 but did not")
	}
}

// TestSMKEXHandshakeSessionsAreIndependent verifies that two separate SMKEX
// handshakes between the same parties produce different session keys, ensuring
// there is no session linkage (forward and backward secrecy between sessions).
func TestSMKEXHandshakeSessionsAreIndependent(t *testing.T) {
	deriveKey := func() []byte {
		clientKP, _ := GenerateKeyPair()
		serverKP, _ := GenerateKeyPair()
		nc, _ := GenerateNonce()
		ns, _ := GenerateNonce()
		raw, _ := clientKP.ComputeSharedSecret(serverKP.PublicKey)
		key, _ := DeriveSessionKey(raw, nc, ns)
		return key
	}

	key1 := deriveKey()
	key2 := deriveKey()

	if bytes.Equal(key1, key2) {
		t.Fatal("two independent SMKEX sessions derived the same session key")
	}
}
