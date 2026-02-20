package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/bobomunteanu/smkex-tor/pkg/smkex"
	torpkg "github.com/bobomunteanu/smkex-tor/pkg/tor"
)

func main() {
	torExePath, err := torpkg.GetTorExecutablePath()
	if err != nil {
		log.Fatalf("tor binary not found: %v", err)
	}

	// Start two independent Tor instances in parallel.
	fmt.Println("Starting two Tor instances (this takes ~1 min)...")
	instances, runDir, err := torpkg.StartInstances(torExePath, "logs/receiver", 2)
	if err != nil {
		log.Fatalf("failed to start Tor instances: %v", err)
	}
	defer os.RemoveAll(runDir)
	defer instances[0].Close()
	defer instances[1].Close()
	fmt.Println("Both Tor instances ready.")

	// Give each hidden service a 3-minute window to be published to Tor.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var (
		listener1  net.Listener
		listener2  net.Listener
		addr1      string
		addr2      string
		listenErr1 error
		listenErr2 error
		wg         sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		listener1, addr1, listenErr1 = torpkg.ListenOnion(instances[0], ctx, 8001)
	}()
	go func() {
		defer wg.Done()
		listener2, addr2, listenErr2 = torpkg.ListenOnion(instances[1], ctx, 8002)
	}()
	wg.Wait()

	if listenErr1 != nil {
		log.Fatalf("failed to start hidden service 1: %v", listenErr1)
	}
	if listenErr2 != nil {
		log.Fatalf("failed to start hidden service 2: %v", listenErr2)
	}

	fmt.Println("\n=== Give these addresses to the sender ===")
	fmt.Printf("Path 1: %s\n", addr1)
	fmt.Printf("Path 2: %s\n", addr2)
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("Waiting for sender to connect on both paths...")

	// ReceiverHandshake blocks until the sender connects on both paths,
	// completes the key exchange, and returns a ready Session.
	session, err := smkex.ReceiverHandshake(listener1, listener2)
	if err != nil {
		log.Fatalf("SMKEX handshake failed: %v", err)
	}
	defer session.Close()

	fmt.Printf("\nHandshake complete!\nSession key: %x\n\n", session.Key())
	fmt.Println("Waiting for encrypted message from sender...")

	plaintext, err := session.ReceiveMessage()
	if err != nil {
		log.Fatalf("failed to receive message: %v", err)
	}

	fmt.Printf("\n=== Decrypted message ===\n%s\n========================\n", plaintext)
}
