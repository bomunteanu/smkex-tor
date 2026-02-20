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

// guardSelectionTimeout is how long we allow for selecting diverse guards and
// waiting for circuits to be verified through them.
const guardSelectionTimeout = 90 * time.Second

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

	// ── Geographic guard pinning ──────────────────────────────────────────
	// Only applies when we have exactly two instances (the SMKEX case).
	// We use instance 0 to query the consensus — both instances see the same
	// network — select two guards from different countries, then pin each
	// instance to its respective guard and wait for circuits to confirm.
	if n == 2 {
		fmt.Println("[guards] selecting geographically diverse entry guards...")
		guard1, guard2, err := SelectDiverseGuards(instances[0])
		if err != nil {
			// Non-fatal: log and continue. Tor will still work, just without
			// guaranteed geographic diversity.
			fmt.Printf("[guards] warning: could not select diverse guards: %v\n", err)
		} else {
			// Pin both instances in parallel.
			var pinErrs [2]error
			var pinWg sync.WaitGroup
			pinWg.Add(2)
			go func() {
				defer pinWg.Done()
				pinErrs[0] = PinGuard(instances[0], guard1)
			}()
			go func() {
				defer pinWg.Done()
				pinErrs[1] = PinGuard(instances[1], guard2)
			}()
			pinWg.Wait()

			for i, e := range pinErrs {
				if e != nil {
					fmt.Printf("[tor%d] warning: could not pin guard: %v\n", i, e)
				}
			}

			// Wait for a BUILT circuit through each pinned guard. This
			// confirms Tor accepted the SETCONF and has an active path.
			// We do this in parallel with a shared timeout.
			fp1, err1 := guard1.FingerprintHex()
			fp2, err2 := guard2.FingerprintHex()
			if err1 == nil && err2 == nil {
				pinWg.Add(2)
				go func() {
					defer pinWg.Done()
					if err := WaitForGuardCircuit(instances[0], fp1, guardSelectionTimeout); err != nil {
						fmt.Printf("[tor0] warning: %v\n", err)
					} else {
						fmt.Printf("[tor0] guard circuit verified: %s\n", guard1.Nickname)
					}
				}()
				go func() {
					defer pinWg.Done()
					if err := WaitForGuardCircuit(instances[1], fp2, guardSelectionTimeout); err != nil {
						fmt.Printf("[tor1] warning: %v\n", err)
					} else {
						fmt.Printf("[tor1] guard circuit verified: %s\n", guard2.Nickname)
					}
				}()
				pinWg.Wait()
			}
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
