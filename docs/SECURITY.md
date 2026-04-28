# Vox Security Model (MVP)

Version: 0.1  
Scope: Pure P2P mode (2–10 peers)

---

## 1. Security Philosophy

- No central trust authority.
- Trust is peer-established via cryptographic identity.
- Group admission is explicit and real-time.
- Security boundaries are WireGuard tunnel + identity signatures.
- Minimize attack surface while preserving decentralization.

---

## 2. Threat Model

### In Scope
- Malicious external attacker
- Malicious invited peer
- Replay attacks
- Packet tampering
- Identity spoofing
- Routing manipulation
- Mesh loop attacks
- Resource exhaustion attempts
- Invite leakage
- NAT probing

### Out of Scope (MVP)
- Nation-state adversary
- Full traffic analysis resistance
- IP address anonymity
- Metadata privacy beyond encryption

---

## 3. Identity Security

Identity = Ed25519 keypair.

Risks:
- Key theft
- Impersonation

Mitigations:
- Encrypted local storage
- Identity never transmitted in plaintext without signature
- All group events and chat messages signed
- Membership certificate signed by admitting peer

---

## 4. Invite Security

Invite capsule:
- Encrypted with group symmetric key
- Signed by creator identity

Risks:
- Invite tampering
- Replay of expired invite
- Password brute force

Mitigations:
- Signature verification
- Expiration timestamp enforcement
- Single-use flag support
- Password hash comparison (constant time)
- Timestamp check during Knock (±30s)

---

## 5. Knock & Handshake Security

### Cleartext joiner WG pubkey
Exposed intentionally to allow DH decryption.

Risk:
- Passive observer sees ephemeral key

Mitigation:
- Ephemeral per session
- No identity leakage

### Replay Attack

Mitigation:
- Timestamp validation ±30s
- Nonce uniqueness
- Membership certificate bound to identity

---

## 6. WireGuard Tunnel

Noise_IKpsk2:
- PSK = group symmetric key

Risks:
- MITM during handshake
- Unauthorized group join

Mitigations:
- PSK binding prevents outsider join
- Identity signature required in Knock
- Admission signed by bootstrap peer

---

## 7. Mesh Routing Security

### Threat: Routing Poisoning
Malicious peer advertises false metrics.

Mitigations:
- LinkStateUpdate must be signed
- Only accept updates from admitted peers
- Cap metric deltas per interval
- Drop extreme outliers

---

### Threat: Loop Amplification
Relay frames circulate infinitely.

Mitigations:
- TTL enforced
- relay_path tracking
- LRU seen-set cache
- Drop if own identity appears in path

---

### Threat: Flooding (voice/chat)

Mitigations:
- Per-peer rate limits
- Disconnect on repeated invalid frames
- Bounded queues in pipeline
- Backpressure isolation for unreliable channels

---

## 8. Presence Privacy

Presence is:
- Only exchanged after admission
- Not globally discoverable

No public directory.

---

## 9. IP Exposure

Peers see each other's IP addresses in P2P mode.

Risk:
- IP harvesting

Mitigation:
- Explicitly documented limitation
- Future bot relay mode optional
- Future TURN support optional

---

## 10. Resource Exhaustion

Risks:
- Large voice frames
- Oversized routing tables
- Message spam

Mitigations:
- Strict packet size validation
- Max group size limit (MVP 10 peers)
- TTL caps
- Fixed upper bounds for caches
- Rate limiting at transport layer

---

## 11. Forward Secrecy

- Ephemeral WG keys per session
- Session keys not reused
- Compromise of old session does not expose future sessions

---

## 12. Secure Coding Requirements

- All signature verification MUST precede state mutation.
- All packet lengths MUST be validated before allocation.
- No unbounded memory growth structures.
- All network parsing must be defensive.
- Voice hot path must avoid allocations to prevent DoS via GC pressure.

---

## 13. Known Security Limitations (MVP)

- No anonymous mode
- No traffic obfuscation
- No onion routing
- No TURN fallback
- No bot relay security hardening
- No automatic invite revocation propagation

---

## 14. Future Hardening

- TURN support
- Relay reputation scoring
- Invite revocation propagation
- Peer trust scoring
- Optional onion-style relay
- Post-quantum key exchange evaluation

---