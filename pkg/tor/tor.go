package torpkg

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/cretz/bine/process"
	"github.com/cretz/bine/tor"
)

func GetTorExecutablePath() (string, error) {
	var exeName string
	if runtime.GOOS == "windows" {
		exeName = "tor.exe"
	} else {
		exeName = "tor"
	}

	localPath := filepath.Join("tor", "tor", exeName)
	if _, err := os.Stat(localPath); err == nil {
		absPath, err := filepath.Abs(localPath)
		if err == nil {
			return absPath, nil
		}
	}

	path, err := exec.LookPath(exeName)
	if err == nil {
		return path, nil
	}

	return "", fmt.Errorf("tor executable not found locally at %s or in PATH", localPath)
}

func StartInstance(exePath, dataDir string) (*tor.Tor, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data dir %s: %w", dataDir, err)
	}

	t, err := tor.Start(context.Background(), &tor.StartConf{
		ProcessCreator: process.NewCreator(exePath),
		DataDir:        dataDir,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start Tor process (%s): %w", dataDir, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := t.EnableNetwork(ctx, true); err != nil {
		t.Close()
		return nil, fmt.Errorf("Tor bootstrap failed (%s): %w", dataDir, err)
	}

	return t, nil
}

func StartInstances(exePath, baseDir string, n int) ([]*tor.Tor, string, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to create base dir %s: %w", baseDir, err)
	}

	runDir, err := os.MkdirTemp(baseDir, "run-")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create run dir under %s: %w", baseDir, err)
	}

	instances := make([]*tor.Tor, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			dataDir := filepath.Join(runDir, fmt.Sprintf("tor%d", i))
			fmt.Printf("[tor%d] bootstrapping...\n", i)
			t, err := StartInstance(exePath, dataDir)
			if err != nil {
				errs[i] = err
				return
			}
			fmt.Printf("[tor%d] ready\n", i)
			instances[i] = t
		}()
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			for _, t := range instances {
				if t != nil {
					t.Close()
				}
			}
			os.RemoveAll(runDir)
			return nil, "", err
		}
	}

	return instances, runDir, nil
}

func ListenOnion(t *tor.Tor, ctx context.Context, localPort int) (net.Listener, string, error) {
	onion, err := t.Listen(ctx, &tor.ListenConf{
		Version3:    true,
		LocalPort:   localPort,
		RemotePorts: []int{localPort},
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to start hidden service on port %d: %w", localPort, err)
	}

	addr := fmt.Sprintf("%s.onion:%d", onion.ID, localPort)
	return onion, addr, nil
}

func DialThroughTor(t *tor.Tor, ctx context.Context, addr string) (net.Conn, error) {
	dialer, err := t.Dialer(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tor dialer: %w", err)
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s through Tor: %w", addr, err)
	}

	return conn, nil
}
