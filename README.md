# SMKEX over Tor

An implementation of the SMKEX key exchange protocol that routes traffic through two independent Tor circuits to protect against man-in-the-middle attacks. Inspired by *"Secure Opportunistic Multipath Key Exchange"* by Costea et al. (CCS '18).

## What is SMKEX?

Standard key exchange happens over a single connection — if someone intercepts it, they can silently sit in the middle and neither side notices. SMKEX splits the handshake across **two separate network paths**. A binding hash ties both paths together, so an attacker who controls only one path gets detected automatically.

This implementation routes those two paths through **different Tor circuits**, each entering the Tor network through an entry guard in a different country. For an attack to succeed, someone would need to simultaneously compromise both circuits — a significantly harder bar to clear.

## How it works

### Setup

The receiver starts two Tor instances and creates two hidden service addresses — one per circuit:

```
Path 1: bfvr2addr7lisjw6bulrt6ecafctvxzpzx6elrnkaexjhp4upfuh7iqd.onion:8001
Path 2: irv6623lq6m3czjjzuetyhxldscuuim6jdasj4f24g6vecc7rglwshid.onion:8002
```

These addresses are shared with the sender out-of-band (e.g. pasted into a terminal). The receiver then waits for connections on both.

### Guard selection

Both sides independently spin up two Tor instances and pin each one to a geographically diverse entry guard:

```
[guards] selected racisz (51.75.33.236) [FR] and emir (45.157.234.132) [DE]
```

Each Tor instance uses a different guard node in a different country, so the two paths don't share infrastructure at the entry point. One path goes in through France, the other through Germany.

### Handshake

The sender dials both `.onion` addresses — one per Tor instance — and the SMKEX handshake runs across both paths simultaneously:

- **Path 1** carries the Diffie-Hellman public keys (`g^x`, `g^y`)
- **Path 2** carries the nonces (`NC`, `NS`) and a binding hash `H(g^x, NC, g^y, NS)`

The receiver uses the binding hash to verify that both paths saw the same session. If an attacker tampered with either path, the hash won't match and the handshake fails. If everything checks out, both sides derive the same session key:

```
Session key: ede832b2602a412b7d6037ae3b96ec71cd7226a775ab62a85dd7df5e772a211d
```

### Messaging

Once the key is established, the sender encrypts a message and sends it. The receiver decrypts and prints it:

```
=== Decrypted message ===
vox populi, vox dei
========================
```

## Security properties

| Property | How |
|---|---|
| Forward secrecy | Fresh X25519 key pair per session |
| Path binding | SHA-256 hash over both paths' session data |
| Tamper detection | Hash mismatch aborts the handshake |
| Message confidentiality | AES-256-GCM with a random nonce per message |
| Replay prevention | Session ID bound into every message as AEAD additional data |
| Path diversity | Two Tor instances with entry guards in different countries |

## Usage

**Receiver** (run first):
```bash
go run ./cmd/receiver/main.go
```
Copy the two `.onion` addresses it prints and give them to the sender.

**Sender:**
```bash
go run ./cmd/sender/main.go <onion1>:<port1> <onion2>:<port2>
```

Startup takes about a minute while both Tor instances bootstrap.

## Reference

Costea, S., Choudary, M. O., Gucea, D., Tackmann, B., & Raiciu, C. (2018). *Secure Opportunistic Multipath Key Exchange.* In Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security (CCS '18), pp. 1867–1884. https://doi.org/10.1145/3243734.3243791
