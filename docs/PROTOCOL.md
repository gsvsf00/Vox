# Vox Protocol (MVP) — WireGuard Handshake + WebRTC DataChannels + Mesh Voice

> Version: 0.1
> Scope: MVP (2–10 peers): identity, invites, join, presence, text chat, voice (Opus) with mesh relays.
> No: bots, offline messages, video/screen share, Virtual LAN, TURN.

## 0. Design rules (MUST)
- Invite URL is NOT authorization.
- A join MUST be admitted by an ONLINE group member during WireGuard-based handshake.
- Presence MUST be visible only after a successful handshake / membership admission.
- Voice transport MUST support mesh relaying by default.
- No central services; only public STUN is allowed for ICE.

## 1. Terms
- Peer: a client node in the group.
- PeerId: Ed25519 public key (32 bytes) used as stable identity.
- WG keypair: ephemeral WireGuard (X25519) keypair per session/app start.
- GroupId: 32 bytes.
- Capsule: opaque encrypted invite blob carried by joiner.
- Bootstrap peer: any online member used for admission and initial signaling relay.

## 2. Cryptography (MVP)
- Identity signing: Ed25519
- Key exchange/encryption helper: X25519
- Invite capsule encryption: XChaCha20-Poly1305 (32B key, 24B nonce)
- Knock packet encryption: crypto_box-style (X25519 + XSalsa20-Poly1305) OR equivalent sealed-box using bootstrap WG pubkey.
- WireGuard handshake: Noise_IKpsk2 w/ group PSK binding (PSK = group symmetric key).

## 3. URL / Invite format
### 3.1 URL
vox://join/<base64url(encrypted_capsule)>?ep=<ip:port>[,<ip:port>...]&bpk=<base64url(wg_pubkey)>

Notes:
- encrypted_capsule: opaque to joiner
- ep: plaintext endpoints so joiner knows where to send the first knock
- bpk: bootstrap’s WG public key (joiner can’t decrypt capsule to learn it)

### 3.2 Capsule (cleartext BEFORE encryption)
Fields (in order):
- invite_id: 16B (UUID)
- group_id: 32B
- creator_identity_pubkey: 32B (Ed25519 pub)
- created_at_ms: 8B
- expires_at_ms: 8B
- flags: 1B
  - bit0 password_required
  - bit1 single_use
- password_hash: 32B (BLAKE2b(password) or zeroed)
- bootstrap_peers: variable
  - count: 1B
  - each:
    - wg_pubkey: 32B
    - ipv4: 4B
    - port: 2B
- creator_signature: 64B Ed25519 signature over all previous fields

Encryption:
- nonce(24B) + XChaCha20-Poly1305(ciphertext + tag)
- key: group symmetric key (32B)

## 4. Connection lifecycle (MVP)
There are 3 phases:

A) Knock (UDP, encrypted)
B) WireGuard tunnel established (Noise_IKpsk2)
C) WebRTC connections formed (ICE+DataChannels), then steady state

### 4.1 Joiner states
- Idle
- ParsedInvite
- Knocking
- KnockAccepted
- WireGuardEstablished
- Admitted (membership cert received)
- WebRTCConnecting
- OnlineInGroup

### 4.2 Bootstrap peer states
- ListeningForKnocks
- ValidatingKnock
- AcceptingOrRejecting
- WireGuardEstablished
- SendingAdmission
- RelayingSignalingForJoiner
- ConnectedPeerOnline

## 5. Handshake packets (UDP + WireGuard)
All UDP Knock packets are encrypted; plaintext layouts below are “pre-encryption”.

### 5.1 UDP: Knock (VOX\x01)
Direction: Joiner -> Bootstrap endpoint (from invite URL)

Fields:
- magic: 4B = 0x564F5801
- version: 1B = 0x01
- joiner_wg_pubkey: 32B
- joiner_identity_pubkey: 32B
- capsule_length: 2B (uint16 LE)
- capsule: var bytes (opaque)
- password_length: 1B
- password: var bytes (0 if none)
- timestamp_ms: 8B (int64 LE)
- identity_signature: 64B (Ed25519 signature over all preceding fields)

Encryption:
- sealed to bootstrap WG pubkey using joiner WG privkey (crypto_box semantics).
Replay protection:
- receiver MUST reject if timestamp outside ±30s window.

### 5.2 UDP: KnockAccept (VOX\x02)
Direction: Bootstrap -> Joiner endpoint

Fields:
- magic: 4B = 0x564F5802
- status: 1B
  - 0 accepted
  - 1 invalid_capsule
  - 2 expired
  - 3 password_wrong
  - 4 group_full
  - 5 rate_limited
- bootstrap_wg_pubkey: 32B
- wg_listen_port: 2B (uint16 LE)
- challenge: 32B random
- bootstrap_identity_signature: 64B (over all preceding fields)

Encryption:
- sealed to joiner WG pubkey using bootstrap WG privkey (crypto_box semantics).

### 5.3 WireGuard handshake (Noise_IKpsk2)
- After KnockAccept, both sides run standard WireGuard handshake.
- PSK MUST be bound to the group (PSK = group symmetric key).
- Once established, a secure tunnel exists for “Admission” messages and initial WebRTC signaling.

### 5.4 Admission (over WireGuard tunnel)
Direction: Bootstrap -> Joiner

Payload (binary or compact JSON/msgpack; MVP recommends binary):
- membership_certificate: signed statement
  - group_id
  - admitted_peer_id (joiner identity pub)
  - admitted_by_peer_id (bootstrap identity pub)
  - admitted_at_ms
  - signature (bootstrap identity key)
- peer_list: list of online peers
  - identity_pubkey
  - username, discriminator
  - wg_pubkey
  - endpoints (best-known)
  - capabilities
  - status
- group_state_snapshot: minimal event log snapshot (members, channels, latest lamport)
- group_symmetric_key: encrypted to joiner identity pubkey (so joiner can decrypt)

### 5.5 AdmissionAck (over WireGuard tunnel)
Direction: Joiner -> Bootstrap
- ack: 1B
- joiner_profile (username, discriminator, capabilities)
- signature (joiner identity key)

## 6. WebRTC phase (signaling without servers)
- Bootstrap acts as temporary signaling relay using existing connections.
- After joiner is admitted, bootstrap forwards SDP + ICE to connect joiner to other peers.

### 6.1 DataChannels (names + semantics)
1) vox-signaling: reliable, ordered
2) vox-chat: reliable, ordered
3) vox-routing: reliable, unordered (plus probes can be unreliable)
4) vox-voice: unreliable, unordered
5) vox-presence: reliable, unordered

ICE:
- STUN only for MVP.
- No TURN for MVP.

## 7. Common header for DataChannel packets (15 bytes)
All packets on WebRTC DataChannels (except the minimal VoiceFrame) use:

Offset | Size | Field
0 | 1 | packet_type
1 | 4 | payload_length (excludes header)
5 | 8 | packet_id (monotonic per sender)
13 | 1 | ttl
14 | 1 | flags (bit0 compressed zstd, bit1 fragmented, bit2 requires_ack)

## 8. Packet type registry (MVP)
0x10 ChatMessage (vox-chat)
0x11 ChatAck (vox-chat)
0x20 VoiceFrame (vox-voice) [minimal header]
0x21 RelayFrame (vox-voice) [common header]
0x30 PresenceUpdate (vox-presence)
0x40 LinkStateUpdate (vox-routing)
0x41 RoutingProbe (vox-routing)
0x42 RoutingPong (vox-routing)
0x50 PeerListSync (vox-signaling)
0x51 SdpOffer (vox-signaling)
0x52 SdpAnswer (vox-signaling)
0x53 IceCandidate (vox-signaling)
0x60 GroupStateSync (vox-signaling)
0x61 GroupEvent (vox-signaling)

## 9. Chat (vox-chat)
### 9.1 ChatMessage (0x10)
- common header
- sender_identity (32B)
- group_id (32B)
- message_id (16B UUID)
- timestamp_ms (8B)
- lamport_clock (8B)
- parent_count (1B)
- parent_event_ids (count * 16B)
- content_length (4B)
- content_utf8 (var)
- signature (64B) over bytes after header up to signature

### 9.2 Delivery (MVP)
- Receiver MAY send ChatAck (0x11) for UI “delivered” hints.
- No offline guarantee: if receiver is offline, message may be missed unless anti-entropy sync later includes it.

## 10. Group state sync (vox-signaling)
- Event-sourced log, signed.
- Anti-entropy:
  - SyncRequest: “these are my latest event IDs/lamport”
  - SyncResponse: “here are missing events”
- MVP can sync full event log due to small size.

## 11. Presence (vox-presence)
PresenceUpdate (0x30):
- common header
- identity (32B)
- status (1B: offline=0 online=1 away=2 dnd=3)
- since_ms (8B)
- signature (64B)

Rule:
- Only send/accept presence from peers that are already admitted.

## 12. Voice (vox-voice)
### 12.1 VoiceFrame (0x20) — minimal header
Offset | Size | Field
0 | 1 | packet_type = 0x20
1 | 4 | sequence_number (uint32 LE)
5 | 8 | timestamp_us (int64 LE)
13 | 32 | sender_identity
45 | 1 | codec_flags (opus=0; bit4 DTX; bit5 FEC)
46 | 1 | channel_id
47 | 2 | frame_length (uint16 LE)
49 | N | opus_payload

### 12.2 RelayFrame (0x21)
- common header (ttl decremented each hop)
- original_sender (32B)
- final_destination (32B or all-0xFF for multicast)
- hop_count (1B)
- relay_path (hop_count * 32B)
- inner_length (2B)
- inner_packet (VoiceFrame bytes)

Loop prevention:
- seen-set cache (LRU ~8192 entries, ~5s TTL)
- TTL <= min(group_size, 7)
- drop if own ID appears in relay_path

## 13. Routing (vox-routing)
### 13.1 LinkStateUpdate (0x40)
- common header
- reporter_identity (32B)
- timestamp_ms (8B)
- lamport_clock (8B)
- link_count (1B)
- each link:
  - peer_identity (32B)
  - rtt_ms (2B)
  - jitter_ms (2B)
  - loss_percent (1B 0..100)
  - stability_pct (1B 0..100)
  - capacity_pct (1B 0..100)
  - status (1B: down=0 up=1 degraded=2)
  - reserved (1B)
- signature (64B)

### 13.2 Probes
- RoutingProbe (0x41) and RoutingPong (0x42) are small, may be unreliable.
- Probes run every ~1s per neighbor.

## 14. Error handling
- Any packet failing signature validation MUST be dropped.
- Any peer sending invalid packets repeatedly SHOULD be disconnected (rate limit).

## 15. Versioning
- Protocol version in Knock packets.
- DataChannel packets can include a “capabilities” bitmap in PeerListSync.

