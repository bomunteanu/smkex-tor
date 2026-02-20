package pkg

import (
	"context"
	"fmt"
	"net"
	"time"

	pkg "github.com/bobomunteanu/smkex-tor/pkg/cryptography"
	"github.com/cretz/bine/tor"
)

func StartHiddenService(t *tor.Tor) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	onion, err := t.Listen(ctx, &tor.ListenConf{Version3: true, LocalPort: 8000})
	if err != nil {
		return "", err
	}

	fmt.Println("Onion service running at:", onion.ID+".onion")

	go func() {
		for {
			conn, err := onion.Accept()
			if err != nil {
				fmt.Println("Failed to accept connection:", err)
				return
			}

			go HandleConnection(conn)
		}
	}()

	return onion.ID + ".onion", nil
}

func HandleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Failed to read data:", err)
		return
	}

	encryptedData := buf[:n]
	key := []byte("example key 1234") // 16 bytes key
	decryptedData, err := pkg.Decrypt(encryptedData, key)
	if err != nil {
		fmt.Println("Failed to decrypt data:", err)
		return
	}

	fmt.Println("Received and decrypted data:", string(decryptedData))
}

// Send data through a specific Tor circuit
func SendThroughTor(data []byte, torInstance *tor.Tor, ctx context.Context, onionAddress string) error {
	dialer, err := torInstance.Dialer(ctx, nil)
	if err != nil {
		return err
	}

	conn, err := dialer.Dial("tcp", onionAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return err
	}

	return nil
}
