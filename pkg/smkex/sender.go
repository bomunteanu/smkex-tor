package smkex

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"

	crypto "github.com/bobomunteanu/smkex-tor/pkg/cryptography"
)

func SenderHandshake(conn1, conn2 net.Conn) ([]byte, error) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("sender: failed to generate key pair: %w", err)
	}

	nc, err := crypto.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("sender: failed to generate nonce: %w", err)
	}

	var sessionID [SessionIDSize]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return nil, fmt.Errorf("sender: failed to generate session ID: %w", err)
	}

	var sendErr1, sendErr2 error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		msg := newMessage(MsgSenderPath1, sessionID, keyPair.PublicKey)
		sendErr1 = msg.WriteTo(conn1)
	}()

	go func() {
		defer wg.Done()
		msg := newMessage(MsgSenderPath2, sessionID, nc)
		sendErr2 = msg.WriteTo(conn2)
	}()

	wg.Wait()

	if sendErr1 != nil {
		return nil, fmt.Errorf("sender: failed to send public key on path 1: %w", sendErr1)
	}
	if sendErr2 != nil {
		return nil, fmt.Errorf("sender: failed to send nonce on path 2: %w", sendErr2)
	}

	var (
		msg1     *Message
		msg2     *Message
		recvErr1 error
		recvErr2 error
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		msg1, recvErr1 = ReadFrom(conn1)
	}()

	go func() {
		defer wg.Done()
		msg2, recvErr2 = ReadFrom(conn2)
	}()

	wg.Wait()

	if recvErr1 != nil {
		return nil, fmt.Errorf("sender: failed to receive reply on path 1: %w", recvErr1)
	}
	if recvErr2 != nil {
		return nil, fmt.Errorf("sender: failed to receive reply on path 2: %w", recvErr2)
	}

	if err := msg1.validate(MsgReceiverPath1, 32); err != nil {
		return nil, fmt.Errorf("sender: invalid path 1 reply: %w", err)
	}

	if err := msg2.validate(MsgReceiverPath2, 64); err != nil {
		return nil, fmt.Errorf("sender: invalid path 2 reply: %w", err)
	}

	// session ids match
	if msg1.SessionID != sessionID {
		return nil, fmt.Errorf("sender: session ID mismatch on path 1 reply")
	}
	if msg2.SessionID != sessionID {
		return nil, fmt.Errorf("sender: session ID mismatch on path 2 reply")
	}

	gy := msg1.Payload
	ns := msg2.Payload[:32]
	receivedHash := msg2.Payload[32:]

	if err := crypto.VerifyBindingHash(keyPair.PublicKey, nc, gy, ns, receivedHash); err != nil {
		return nil, fmt.Errorf("sender: %w", err)
	}

	sharedSecret, err := keyPair.ComputeSharedSecret(gy)
	if err != nil {
		return nil, fmt.Errorf("sender: failed to compute shared secret: %w", err)
	}

	sessionKey, err := crypto.DeriveSessionKey(sharedSecret, nc, ns)
	if err != nil {
		return nil, fmt.Errorf("sender: failed to derive session key: %w", err)
	}

	return sessionKey, nil
}
