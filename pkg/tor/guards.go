package torpkg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cretz/bine/control"
	"github.com/cretz/bine/tor"
)

type RelayInfo struct {
	Nickname       string
	FingerprintB64 string
	Address        string
	ORPort         int
	DirPort        int
	Published      string
	Flags          []string
	Bandwidth      int
}

func (r *RelayInfo) HasFlag(flag string) bool {
	for _, f := range r.Flags {
		if f == flag {
			return true
		}
	}
	return false
}

func (r *RelayInfo) FingerprintHex() (string, error) {
	b64 := r.FingerprintB64
	switch len(b64) % 4 {
	case 2:
		b64 += "=="
	case 3:
		b64 += "="
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("failed to decode fingerprint %q: %w", r.FingerprintB64, err)
	}
	return strings.ToUpper(hex.EncodeToString(raw)), nil
}

func QueryRelays(t *tor.Tor) ([]RelayInfo, error) {
	info, err := t.Control.GetInfo("ns/all")
	if err != nil {
		return nil, fmt.Errorf("GETINFO ns/all failed: %w", err)
	}
	if len(info) == 0 || info[0].Key != "ns/all" {
		return nil, fmt.Errorf("unexpected GETINFO response: %d entries", len(info))
	}

	body := strings.TrimLeft(info[0].Val, "\r\n")
	lines := strings.Split(body, "\n")

	var relays []RelayInfo
	var current *RelayInfo

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "r "):
			if current != nil {
				relays = append(relays, *current)
			}
			current = parseRLine(line)
		case strings.HasPrefix(line, "s ") && current != nil:
			current.Flags = parseSLine(line)
		case strings.HasPrefix(line, "w ") && current != nil:
			current.Bandwidth = parseWLine(line)
		}
	}
	if current != nil {
		relays = append(relays, *current)
	}

	return relays, nil
}

func LookupCountry(t *tor.Tor, ip string) (string, error) {
	info, err := t.Control.GetInfo("ip-to-country/" + ip)
	if err != nil {
		return "", nil
	}
	if len(info) == 0 {
		return "", nil
	}
	return strings.ToLower(strings.TrimSpace(info[0].Val)), nil
}

func SelectDiverseGuards(t *tor.Tor) (RelayInfo, RelayInfo, error) {
	relays, err := QueryRelays(t)
	if err != nil {
		return RelayInfo{}, RelayInfo{}, fmt.Errorf("failed to query relays: %w", err)
	}

	var candidates []RelayInfo
	for _, r := range relays {
		if r.HasFlag("Guard") && r.HasFlag("Stable") && r.HasFlag("Running") {
			candidates = append(candidates, r)
		}
	}
	if len(candidates) < 2 {
		return RelayInfo{}, RelayInfo{}, fmt.Errorf(
			"not enough guard candidates in consensus: found %d", len(candidates))
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Bandwidth > candidates[j].Bandwidth
	})

	limit := 100
	if len(candidates) < limit {
		limit = len(candidates)
	}

	var guard1, guard2 RelayInfo
	country1 := ""

	for _, c := range candidates[:limit] {
		country, err := LookupCountry(t, c.Address)
		if err != nil {
			return RelayInfo{}, RelayInfo{}, err
		}
		if country == "" {
			continue
		}

		if country1 == "" {
			guard1 = c
			country1 = country
			continue
		}

		if country != country1 {
			guard2 = c
			fmt.Printf("[guards] selected %s (%s) [%s] and %s (%s) [%s]\n",
				guard1.Nickname, guard1.Address, strings.ToUpper(country1),
				guard2.Nickname, guard2.Address, strings.ToUpper(country))
			return guard1, guard2, nil
		}
	}

	return RelayInfo{}, RelayInfo{}, fmt.Errorf(
		"could not find two guards from different countries in top %d candidates "+
			"(all appear to be in %s)", limit, strings.ToUpper(country1))
}

func PinGuard(t *tor.Tor, guard RelayInfo) error {
	fpHex, err := guard.FingerprintHex()
	if err != nil {
		return fmt.Errorf("invalid guard fingerprint: %w", err)
	}

	if err := t.Control.SetConf(
		control.NewKeyVal("EntryNodes", "$"+fpHex),
		control.NewKeyVal("StrictNodes", "1"),
	); err != nil {
		return fmt.Errorf("SETCONF EntryNodes/StrictNodes failed: %w", err)
	}

	if err := t.Control.Signal("NEWNYM"); err != nil {
		return fmt.Errorf("SIGNAL NEWNYM failed: %w", err)
	}

	fmt.Printf("[guards] pinned entry guard: %s (%s) $%s\n",
		guard.Nickname, guard.Address, fpHex)
	return nil
}

func WaitForGuardCircuit(t *tor.Tor, expectedFpHex string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok, err := hasCircuitWithGuard(t, expectedFpHex)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("no BUILT circuit through guard $%s appeared within %s",
		expectedFpHex, timeout)
}
func hasCircuitWithGuard(t *tor.Tor, expectedFpHex string) (bool, error) {
	info, err := t.Control.GetInfo("circuit-status")
	if err != nil {
		return false, fmt.Errorf("GETINFO circuit-status failed: %w", err)
	}

	body := ""
	if len(info) > 0 {
		body = strings.TrimLeft(info[0].Val, "\r\n")
	}

	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 || parts[1] != "BUILT" {
			continue
		}

		hops := strings.Split(parts[2], ",")
		if len(hops) == 0 {
			continue
		}

		firstHop := strings.TrimPrefix(hops[0], "$")
		if idx := strings.Index(firstHop, "~"); idx >= 0 {
			firstHop = firstHop[:idx]
		}

		if strings.EqualFold(firstHop, expectedFpHex) {
			return true, nil
		}
	}

	return false, nil
}

func parseRLine(line string) *RelayInfo {
	parts := strings.Fields(line)
	if len(parts) < 9 {
		return &RelayInfo{Nickname: "?"}
	}
	orPort, _ := strconv.Atoi(parts[7])
	dirPort, _ := strconv.Atoi(parts[8])
	return &RelayInfo{
		Nickname:       parts[1],
		FingerprintB64: parts[2],
		Published:      parts[4] + " " + parts[5],
		Address:        parts[6],
		ORPort:         orPort,
		DirPort:        dirPort,
	}
}

func parseSLine(line string) []string {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	return parts[1:]
}

func parseWLine(line string) int {
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "Bandwidth=") {
			n, err := strconv.Atoi(strings.TrimPrefix(field, "Bandwidth="))
			if err == nil {
				return n
			}
		}
	}
	return 0
}
