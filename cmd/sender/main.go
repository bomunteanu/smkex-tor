package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bobomunteanu/smkex-tor/pkg/smkex"
	torpkg "github.com/bobomunteanu/smkex-tor/pkg/tor"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: sender <path1-onion-addr> <path2-onion-addr> [message]\n  e.g. sender abc.onion:8001 xyz.onion:8002")
	}
	addr1 := os.Args[1]
	addr2 := os.Args[2]

	torExePath, err := torpkg.GetTorExecutablePath()
	if err != nil {
		log.Fatalf("tor binary not found: %v", err)
	}

	// Start two independent Tor instances in parallel.
	fmt.Println("Starting two Tor instances (this takes ~1 min)...")
	instances, runDir, err := torpkg.StartInstances(torExePath, "logs/sender", 2)
	if err != nil {
		log.Fatalf("failed to start Tor instances: %v", err)
	}
	defer os.RemoveAll(runDir)
	defer instances[0].Close()
	defer instances[1].Close()
	fmt.Println("Both Tor instances ready.")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var (
		conn1    net.Conn
		conn2    net.Conn
		dialErr1 error
		dialErr2 error
		wg       sync.WaitGroup
	)

	fmt.Printf("Dialing path 1 (%s) via tor0...\n", addr1)
	fmt.Printf("Dialing path 2 (%s) via tor1...\n", addr2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		conn1, dialErr1 = torpkg.DialThroughTor(instances[0], ctx, addr1)
	}()
	go func() {
		defer wg.Done()
		conn2, dialErr2 = torpkg.DialThroughTor(instances[1], ctx, addr2)
	}()
	wg.Wait()

	if dialErr1 != nil {
		log.Fatalf("failed to dial path 1: %v", dialErr1)
	}
	if dialErr2 != nil {
		log.Fatalf("failed to dial path 2: %v", dialErr2)
	}
	// conn2 is closed inside SenderHandshake once the handshake completes.
	// conn1 is owned by the returned Session; do not close it directly.
	defer conn2.Close()

	fmt.Println("Connected on both paths. Starting SMKEX handshake...")

	session, err := smkex.SenderHandshake(conn1, conn2)
	if err != nil {
		log.Fatalf("SMKEX handshake failed: %v", err)
	}
	defer session.Close()

	fmt.Printf("\nHandshake complete!\nSession key: %x\n\n", session.Key())

	// ------------------------------------------------------------------
	// Post-handshake: encrypt and send a message to the receiver.
	// ------------------------------------------------------------------
	var plaintext string
	if len(os.Args) >= 4 {
		// Message supplied as trailing command-line arguments.
		plaintext = strings.Join(os.Args[3:], " ")
	} else {
		// Prompt the user interactively.
		fmt.Print("Enter message to send: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			plaintext = scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("failed to read message from stdin: %v", err)
		}
	}

	if err := session.SendMessage([]byte(plaintext)); err != nil {
		log.Fatalf("failed to send encrypted message: %v", err)
	}

	fmt.Println("Message sent (encrypted).")
}
