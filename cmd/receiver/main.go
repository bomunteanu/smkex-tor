package main

import (
	"context"
	"fmt"
	"time"

	pkg "github.com/bobomunteanu/smkex-tor/pkg/tor"
	"github.com/cretz/bine/process"
	"github.com/cretz/bine/tor"
)

func main() {
	torExePath := `C:\Users\bogda\Desktop\smkex-tor\tor\tor\tor.exe`

	// Start Tor instance
	t, err := tor.Start(context.TODO(), &tor.StartConf{ProcessCreator: process.NewCreator(torExePath)})
	if err != nil {
		panic(err)
	}
	defer t.Close()

	// Enable Tor network
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := t.EnableNetwork(ctx, true); err != nil {
		panic(err)
	}

	// Start Hidden Service
	onionAddress, err := pkg.StartHiddenService(t)
	if err != nil {
		panic(err)
	}

	fmt.Println("Hidden service is available at:", onionAddress)

	// Keep the service running
	select {}
}
