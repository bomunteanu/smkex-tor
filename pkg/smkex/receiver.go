package smkex

import (
	"fmt"
	"net"
	"sync"
	"time"

	crypto "github.com/bobomunteanu/smkex-tor/pkg/cryptography"
)

// sessionHalf holds whichever half of a handshake arrived first while
// waiting for the other half on the other connection.
type sessionHalf struct {
	msg       *Message
	arrivedAt time.Time
}

type pendingSessions struct {
	mu    sync.Mutex
	path1 map[[SessionIDSize]byte]*sessionHalf
	path2 map[[SessionIDSize]byte]*sessionHalf
}

func newPendingSessions() *pendingSessions {
	return &pendingSessions{
		path1: make(map[[SessionIDSize]byte]*sessionHalf),
		path2: make(map[[SessionIDSize]byte]*sessionHalf),
	}
}

const sessionTimeout = 2 * time.Minute

func (ps *pendingSessions) tryPair(msg *Message, path int) (*Message, *Message, bool) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.evictExpired()

	id := msg.SessionID
	half := &sessionHalf{msg: msg, arrivedAt: time.Now()}

	if path == 1 {
		if other, ok := ps.path2[id]; ok {
			delete(ps.path2, id)
			return msg, other.msg, true
		}
		ps.path1[id] = half
		return nil, nil, false
	}

	if other, ok := ps.path1[id]; ok {
		delete(ps.path1, id)
		return other.msg, msg, true
	}
	ps.path2[id] = half
	return nil, nil, false
}

func (ps *pendingSessions) evictExpired() {
	cutoff := time.Now().Add(-sessionTimeout)
	for id, h := range ps.path1 {
		if h.arrivedAt.Before(cutoff) {
			delete(ps.path1, id)
		}
	}
	for id, h := range ps.path2 {
		if h.arrivedAt.Before(cutoff) {
			delete(ps.path2, id)
		}
	}
}

// ReceiverHandshake accepts one connection on each listener, completes the
// SMKEX handshake, and returns a Session ready for encrypted data transfer.
//
// The path-2 connection is closed after the handshake. The path-1 connection
// is transferred into the returned Session — use Session.Close() to release it.
func ReceiverHandshake(listener1, listener2 net.Listener) (*Session, error) {
	pending := newPendingSessions()

	type pairedResult struct {
		msg1 *Message
		msg2 *Message
	}
	paired := make(chan pairedResult, 1)
	errCh := make(chan error, 2)

	acceptAndRead := func(ln net.Listener, path int, connOut *net.Conn) {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- fmt.Errorf("receiver: failed to accept on path %d: %w", path, err)
			return
		}
		*connOut = conn

		msg, err := ReadFrom(conn)
		if err != nil {
			conn.Close()
			errCh <- fmt.Errorf("receiver: failed to read message on path %d: %w", path, err)
			return
		}

		var expectedType MessageType
		var expectedPayload int
		if path == 1 {
			expectedType = MsgSenderPath1
			expectedPayload = 32 // g^x
		} else {
			expectedType = MsgSenderPath2
			expectedPayload = 32 // NC
		}
		if err := msg.validate(expectedType, expectedPayload); err != nil {
			conn.Close()
			errCh <- fmt.Errorf("receiver: invalid message on path %d: %w", path, err)
			return
		}

		msg1, msg2, complete := pending.tryPair(msg, path)
		if complete {
			paired <- pairedResult{msg1: msg1, msg2: msg2}
		}
	}

	var conn1, conn2 net.Conn

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); acceptAndRead(listener1, 1, &conn1) }()
	go func() { defer wg.Done(); acceptAndRead(listener2, 2, &conn2) }()
	wg.Wait()

	select {
	case err := <-errCh:
		if conn1 != nil {
			conn1.Close()
		}
		if conn2 != nil {
			conn2.Close()
		}
		return nil, err
	default:
	}

	var result pairedResult
	select {
	case result = <-paired:
	default:
		return nil, fmt.Errorf("receiver: handshake messages could not be paired")
	}

	// Extract g^x and NC from the paired messages.
	gx := result.msg1.Payload
	nc := result.msg2.Payload
	sessionID := result.msg1.SessionID

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		conn1.Close()
		conn2.Close()
		return nil, fmt.Errorf("receiver: failed to generate key pair: %w", err)
	}

	ns, err := crypto.GenerateNonce()
	if err != nil {
		conn1.Close()
		conn2.Close()
		return nil, fmt.Errorf("receiver: failed to generate nonce: %w", err)
	}

	bindingHash := crypto.BindingHash(gx, nc, keyPair.PublicKey, ns)
	path2Payload := append(ns, bindingHash...)

	var sendErr1, sendErr2 error
	var sendWg sync.WaitGroup
	sendWg.Add(2)

	go func() {
		defer sendWg.Done()
		msg := newMessage(MsgReceiverPath1, sessionID, keyPair.PublicKey)
		sendErr1 = msg.WriteTo(conn1)
	}()

	go func() {
		defer sendWg.Done()
		msg := newMessage(MsgReceiverPath2, sessionID, path2Payload)
		sendErr2 = msg.WriteTo(conn2)
	}()

	sendWg.Wait()

	// Path 2 is no longer needed — close it now.
	conn2.Close()

	if sendErr1 != nil {
		conn1.Close()
		return nil, fmt.Errorf("receiver: failed to send public key on path 1: %w", sendErr1)
	}
	if sendErr2 != nil {
		conn1.Close()
		return nil, fmt.Errorf("receiver: failed to send nonce+hash on path 2: %w", sendErr2)
	}

	sharedSecret, err := keyPair.ComputeSharedSecret(gx)
	if err != nil {
		conn1.Close()
		return nil, fmt.Errorf("receiver: failed to compute shared secret: %w", err)
	}

	sessionKey, err := crypto.DeriveSessionKey(sharedSecret, nc, ns)
	if err != nil {
		conn1.Close()
		return nil, fmt.Errorf("receiver: failed to derive session key: %w", err)
	}

	return &Session{
		sessionID: sessionID,
		key:       sessionKey,
		conn:      conn1,
	}, nil
}
