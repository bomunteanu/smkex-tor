package smkex

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MessageType identifies which of the four SMKEX protocol messages is on the wire
type MessageType uint8

const (
	// MsgSenderPath1 is sent by the sender on connection 1
	// Payload: sender's X25519 public key (g^x), 32 bytes
	MsgSenderPath1 MessageType = 0x01

	// MsgSenderPath2 is sent by the sender on connection 2
	// Payload: sender's nonce NC, 32 bytes
	MsgSenderPath2 MessageType = 0x02

	// MsgReceiverPath1 is sent by the receiver back on connection 1
	// Payload: receiver's X25519 public key (g^y), 32 bytes
	MsgReceiverPath1 MessageType = 0x03

	// MsgReceiverPath2 is sent by the receiver back on connection 2
	// Payload: receiver's nonce NS (32 bytes) || binding hash H(gx,NC,gy,NS) (32 bytes)
	MsgReceiverPath2 MessageType = 0x04
)

// length of the session identifier in bytes
const SessionIDSize = 16

// type (1 byte) | session ID (16 bytes) | payload length (2 bytes) | payload (N bytes)

const headerSize = 1 + SessionIDSize + 2

// in-memory representation of a SMKEX wire message
type Message struct {
	Type      MessageType
	SessionID [SessionIDSize]byte
	Payload   []byte
}

func (m *Message) WriteTo(w io.Writer) error {
	payloadLen := len(m.Payload)
	if payloadLen > 0xFFFF {
		return fmt.Errorf("payload too large: %d bytes", payloadLen)
	}

	buf := make([]byte, headerSize+payloadLen)
	buf[0] = byte(m.Type)
	copy(buf[1:1+SessionIDSize], m.SessionID[:])
	binary.BigEndian.PutUint16(buf[1+SessionIDSize:], uint16(payloadLen))
	copy(buf[headerSize:], m.Payload)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	return nil
}

func ReadFrom(r io.Reader) (*Message, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("failed to read message header: %w", err)
	}

	msgType := MessageType(header[0])
	var sessionID [SessionIDSize]byte
	copy(sessionID[:], header[1:1+SessionIDSize])
	payloadLen := binary.BigEndian.Uint16(header[1+SessionIDSize:])

	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("failed to read message payload: %w", err)
		}
	}

	return &Message{
		Type:      msgType,
		SessionID: sessionID,
		Payload:   payload,
	}, nil
}

func newMessage(msgType MessageType, sessionID [SessionIDSize]byte, payload []byte) *Message {
	return &Message{
		Type:      msgType,
		SessionID: sessionID,
		Payload:   payload,
	}
}

func (m *Message) validate(expectedType MessageType, expectedPayloadSize int) error {
	if m.Type != expectedType {
		return fmt.Errorf("unexpected message type: got 0x%02X, want 0x%02X", m.Type, expectedType)
	}
	if len(m.Payload) != expectedPayloadSize {
		return fmt.Errorf("unexpected payload size for type 0x%02X: got %d bytes, want %d",
			m.Type, len(m.Payload), expectedPayloadSize)
	}
	return nil
}
