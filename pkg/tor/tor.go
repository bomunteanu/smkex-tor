package pkg

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	pkg "github.com/bobomunteanu/smkex-tor/pkg/cryptography"
	"github.com/cretz/bine/tor"
)

// GetTorExecutablePath returns the path to the Tor executable based on the OS.
// It checks for a local binary first, then falls back to looking in the PATH.
func GetTorExecutablePath() (string, error) {
	var exeName string
	if runtime.GOOS == "windows" {
		exeName = "tor.exe"
	} else {
		exeName = "tor"
	}

	// 1. Check relative path from project root: tor/tor/tor(.exe)
	// We assume the application is run from the project root.
	localPath := filepath.Join("tor", "tor", exeName)
	if _, err := os.Stat(localPath); err == nil {
		absPath, err := filepath.Abs(localPath)
		if err == nil {
			return absPath, nil
		}
	}

	// 2. Check in PATH
	path, err := exec.LookPath(exeName)
	if err == nil {
		return path, nil
	}

	return "", fmt.Errorf("tor executable not found locally at %s or in PATH", localPath)
}

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
	decryptedData, err := pkg.Decrypt(encryptedData, key, nil)
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
