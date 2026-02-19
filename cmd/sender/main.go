package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	crypto "github.com/bobomunteanu/smkex-tor/pkg/cryptography"
	torpkg "github.com/bobomunteanu/smkex-tor/pkg/tor"
	"github.com/cretz/bine/process"
	"github.com/cretz/bine/tor"
)

func main() {
	torExePath, err := torpkg.GetTorExecutablePath()

	// Start Tor instance
	torInstance, err := tor.Start(context.Background(), &tor.StartConf{
		ProcessCreator:  process.NewCreator(torExePath),
		TempDataDirBase: "logs",
	})
	if err != nil {
		panic(fmt.Errorf("failed to start Tor instance: %w", err))
	}

	// Ensure Tor instance is closed when main function exits
	defer torInstance.Close()

	// Enable Tor network
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := torInstance.EnableNetwork(ctx, true); err != nil {
		panic(fmt.Errorf("failed to enable Tor network: %w", err))
	}

	// Encrypt data
	key := []byte("example key 1234") // 16 bytes key
	data := []byte("Hello, World!")
	encryptedData, err := crypto.Encrypt(data, key, nil)
	if err != nil {
		panic(fmt.Errorf("encryption failed: %w", err))
	}

	// Hidden service address of the receiver
	onionAddress := "ixa5wwzqwdgvcm3cpoytf622ladfamz63yjc73bwi25egqxobhp7bvid.onion:8000"

	// Use wait group to wait for goroutines to finish
	var wg sync.WaitGroup
	wg.Add(2)

	// Send encrypted data through two different Tor circuits
	go func() {
		defer wg.Done()
		err := torpkg.SendThroughTor(encryptedData, torInstance, ctx, onionAddress)
		if err != nil {
			fmt.Println("Error sending data:", err)
		}
	}()

	go func() {
		defer wg.Done()
		err := torpkg.SendThroughTor(encryptedData, torInstance, ctx, onionAddress)
		if err != nil {
			fmt.Println("Error sending data:", err)
		}
	}()

	// Wait for all goroutines to finish
	wg.Wait()
}
