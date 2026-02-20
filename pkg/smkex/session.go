package smkex

import (
	"fmt"
	"net"

	crypto "github.com/bobomunteanu/smkex-tor/pkg/cryptography"
)

type Session struct {
	sessionID [SessionIDSize]byte
	key       []byte
	conn      net.Conn
}

func (s *Session) Key() []byte {
	k := make([]byte, len(s.key))
	copy(k, s.key)
	return k
}

func (s *Session) aad() []byte {
	b := make([]byte, SessionIDSize)
	copy(b, s.sessionID[:])
	return b
}

func (s *Session) SendMessage(plaintext []byte) error {
	ciphertext, err := crypto.Encrypt(plaintext, s.key, s.aad())
	if err != nil {
		return fmt.Errorf("session: encrypt: %w", err)
	}

	msg := newMessage(MsgData, s.sessionID, ciphertext)
	if err := msg.WriteTo(s.conn); err != nil {
		return fmt.Errorf("session: send: %w", err)
	}
	return nil
}

func (s *Session) ReceiveMessage() ([]byte, error) {
	msg, err := ReadFrom(s.conn)
	if err != nil {
		return nil, fmt.Errorf("session: recv: %w", err)
	}

	if msg.Type != MsgData {
		return nil, fmt.Errorf("session: unexpected message type 0x%02X (want MsgData 0x%02X)",
			msg.Type, MsgData)
	}
	if msg.SessionID != s.sessionID {
		return nil, fmt.Errorf("session: session ID mismatch in data message")
	}

	plaintext, err := crypto.Decrypt(msg.Payload, s.key, s.aad())
	if err != nil {
		return nil, fmt.Errorf("session: decrypt: %w", err)
	}
	return plaintext, nil
}

func (s *Session) Close() error {
	return s.conn.Close()
}
