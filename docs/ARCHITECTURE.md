# Vox — MVP Architecture Design Document

> **Version:** 0.1-draft
> **Target:** .NET 10 / MAUI + Blazor Hybrid / Tailwind CSS
> **Scope:** MVP — 2-10 users, text chat, voice, presence, no video/screen share/bots/LAN
> **Date:** 2026-02-18

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Layers](#2-architecture-layers)
3. [Module Boundaries & Dependencies](#3-module-boundaries--dependencies)
4. [Identity System](#4-identity-system)
5. [Invite & Join Protocol](#5-invite--join-protocol)
6. [WireGuard Handshake Flow](#6-wireguard-handshake-flow)
7. [WebRTC Integration](#7-webrtc-integration)
8. [Group State Management](#8-group-state-management)
9. [Mesh Routing Algorithm](#9-mesh-routing-algorithm)
10. [Packet Structures (Wire Format)](#10-packet-structures-wire-format)
11. [Voice Pipeline](#11-voice-pipeline)
12. [.NET Abstractions](#12-net-abstractions)
13. [Project Folder Structure](#13-project-folder-structure)
14. [Threading & Concurrency Model](#14-threading--concurrency-model)
15. [Performance Risks & Mitigations](#15-performance-risks--mitigations)
16. [Dependency Map](#16-dependency-map)
17. [Future Extensibility](#17-future-extensibility)
18. [Known Limitations & Trade-offs](#18-known-limitations--trade-offs)

---

## 1. System Overview

Vox is a decentralized, peer-to-peer voice and text communication application. There are no always-on servers. Groups exist as distributed state across online members. A group is reachable only when at least one member is online.

### 1.1 Design Principles

| Principle | Implication |
|---|---|
| No central authority | Identity is local keypair. Group state is event-sourced and signed. |
| WireGuard for authentication | Every peer connection starts with a Noise_IKpsk2-compatible handshake. No peer is trusted without cryptographic proof. |
| WebRTC for transport | Media and data channels handle NAT traversal (ICE), adaptive bitrate, and jitter buffering. |
| Mesh-routed voice | Audio frames are relayed through peers when direct paths are suboptimal. Path selection is dynamic. |
| Invite ≠ authorization | Invite URLs carry opaque encrypted capsules. Admission requires real-time handshake with an online member. |
| Eventually consistent state | Group state converges via signed, causally-ordered events. No consensus protocol needed for MVP group sizes. |

### 1.2 System Context

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                             │
│                                                             │
│   ┌──────────┐    WireGuard    ┌──────────┐                 │
│   │  Peer A   │◄──────────────►│  Peer B   │                │
│   │ (creator) │    WebRTC      │ (member)  │                │
│   └─────┬────┘                 └─────┬────┘                 │
│         │                            │                      │
│         │  WireGuard + WebRTC        │ WireGuard + WebRTC   │
│         │                            │                      │
│         ▼                            ▼                      │
│   ┌──────────┐    WebRTC       ┌──────────┐                 │
│   │  Peer C   │◄──────────────►│  Peer D   │                │
│   │ (member)  │  (via relay B) │ (member)  │                │
│   └──────────┘                 └──────────┘                 │
│                                                             │
│   ┌──────────────────┐                                      │
│   │ STUN Server(s)   │  (public, stateless, read-only)      │
│   │ (stun.l.google…) │                                      │
│   └──────────────────┘                                      │
└─────────────────────────────────────────────────────────────┘
```

**External dependencies:** Only public STUN servers for ICE candidate discovery. No TURN for MVP. No DNS, no registries, no central indexing.

### 1.3 Network Topology

For a group of N peers, the topology is a **partial mesh**:

- Each peer attempts direct WebRTC connections to all other peers.
- If a direct connection fails (restrictive NAT) or has poor quality, traffic routes through relay peers.
- The routing table is maintained per-peer and updated based on measured link quality.
- Worst case for 10 users: $\binom{10}{2} = 45$ potential edges. In practice, most will succeed as direct connections.

---

## 2. Architecture Layers

```
┌────────────────────────────────────────────────────────┐
│                    UI Layer                             │
│         Blazor Hybrid Components + Tailwind            │
├────────────────────────────────────────────────────────┤
│                 Application Layer                      │
│     GroupService  ChatService  VoiceService  Presence   │
├───────────────┬──────────────┬─────────────────────────┤
│  Group State  │   Routing    │    Voice Pipeline       │
│  (CRDT/Event) │  (Mesh)      │  (Capture→Encode→Mix)  │
├───────────────┴──────────────┴─────────────────────────┤
│                 Transport Layer                         │
│         WebRTC (DataChannel + MediaChannel)             │
├────────────────────────────────────────────────────────┤
│              Authentication Layer                      │
│      WireGuard-compatible Noise Handshake + Knock      │
├────────────────────────────────────────────────────────┤
│                 Crypto Layer                            │
│     libsodium (Ed25519, X25519, XChaCha20-Poly1305)    │
├────────────────────────────────────────────────────────┤
│               Platform Layer                           │
│    Audio I/O (NAudio/platform)  ·  Sockets  ·  Storage │
└────────────────────────────────────────────────────────┘
```

Data flow direction is bidirectional at every boundary. The authentication layer is traversed only during connection establishment; steady-state traffic flows through the transport layer.

---

## 3. Module Boundaries & Dependencies

### 3.1 Module Dependency Graph

```
Vox.App ──► Vox.Chat ──► Vox.Core
  │            │
  │            ▼
  ├──► Vox.Voice ──► Vox.Core
  │       │
  │       ▼
  ├──► Vox.Network ──► Vox.Core
  │       │
  │       ▼
  │   Vox.Network.Native (P/Invoke: Opus, RNNoise, Noise)
  │
  ▼
Vox.Core (zero external dependencies)
```

### 3.2 Module Responsibilities

| Module | Responsibility | May Depend On |
|---|---|---|
| **Vox.Core** | Identity, cryptography, packet definitions, serialization, group state types, event model, configuration. Zero platform dependencies. | libsodium (via P/Invoke) |
| **Vox.Network** | WireGuard-compatible handshake (Noise_IKpsk2), knock protocol, WebRTC session management, ICE/STUN, mesh routing engine, transport abstraction, NAT traversal. | Vox.Core |
| **Vox.Voice** | Audio capture, Opus encode/decode, RNNoise suppression, jitter buffer, audio mixing, playback, push-to-talk gating, mic device selection. | Vox.Core, Vox.Network (for sending/receiving frames) |
| **Vox.Chat** | Message creation, ordering, deduplication, history storage (local SQLite), message signing and verification. | Vox.Core, Vox.Network (transport) |
| **Vox.App** | MAUI host, Blazor Hybrid UI, Tailwind styling, DI registration, platform services, view models, app lifecycle. | All modules |

### 3.3 Boundary Rules

1. **Vox.Core** has no upward dependencies. It defines interfaces that upper layers implement.
2. **Vox.Network** exposes `ITransportService` consumed by Voice and Chat. It never references Voice or Chat types.
3. **Vox.Voice** and **Vox.Chat** are peers — neither depends on the other.
4. **Vox.App** is the composition root. All DI wiring happens here.
5. Native interop (P/Invoke) is isolated behind interfaces. Test doubles replace native code in unit tests.

---

## 4. Identity System

### 4.1 Identity Structure

```
Username#1234
    │     │
    │     └── Discriminator: uint16, randomly assigned at creation, visually 4-digit zero-padded
    │
    └── Username: 2-32 chars, Unicode, no '#' character
```

**Backing keypair:**

| Key | Algorithm | Size | Purpose |
|---|---|---|---|
| Identity signing key | Ed25519 | 32B pub / 64B priv | Sign all protocol messages, prove identity |
| Identity encryption key | X25519 (derived from Ed25519) | 32B | Encrypt peer-to-peer payloads during knock |
| WireGuard key | X25519 | 32B pub / 32B priv | WireGuard Noise handshake, separate from identity | 

The identity signing key is the canonical peer identity. The WireGuard key is ephemeral per-session (regenerated on each app start) to provide forward secrecy for the transport layer. The identity key is long-lived and stored encrypted at rest.

### 4.2 Key Storage

```
%APPDATA%/Vox/identity/
├── identity.key          # Ed25519 private key, encrypted with passphrase via XChaCha20-Poly1305
├── identity.pub          # Ed25519 public key, plaintext
├── profile.json          # { username, discriminator, created_at }
└── groups/
    ├── <group-id-hex>/
    │   ├── group.key     # Group symmetric key, encrypted with identity key
    │   ├── state.db      # SQLite: event log, member list, chat history
    │   └── peers.json    # Last-known peer endpoints
    └── ...
```

### 4.3 Identity Derivation

```
seed (32 random bytes, generated once)
  │
  ├─► Ed25519 keypair (identity)
  │     └─► X25519 keypair (derived, for encryption)
  │
  └─► WireGuard X25519 keypair (separate derivation, per-session)
```

The identity seed is the root secret. Losing it means losing the identity. No recovery mechanism exists (by design — no central authority).

---

## 5. Invite & Join Protocol

### 5.1 Invite URL Format

```
vox://join/<base64url-encoded-invite-blob>
```

The invite blob is **not** the authorization. It is an opaque capsule readable only by existing group members.

### 5.2 Invite Blob Structure (Cleartext Before Encryption)

```
┌──────────────────────────────────────────────────┐
│  invite_id          : 16 bytes (UUID)            │
│  group_id           : 32 bytes                   │
│  creator_identity   : 32 bytes (Ed25519 pubkey)  │
│  created_at         : 8 bytes (Unix ms)          │
│  expires_at         : 8 bytes (Unix ms)          │
│  flags              : 1 byte                     │
│    bit 0: password_required                      │
│    bit 1: single_use                             │
│  password_hash      : 32 bytes (BLAKE2b of       │
│                       password, or zeroed)        │
│  bootstrap_peers    : variable                   │
│    count            : 1 byte                     │
│    for each:                                     │
│      wg_pubkey      : 32 bytes                   │
│      ipv4           : 4 bytes                    │
│      port           : 2 bytes                    │
│  creator_signature  : 64 bytes (Ed25519 sig      │
│                       over all preceding fields)  │
└──────────────────────────────────────────────────┘
```

**Encryption:** The entire blob is encrypted with the group symmetric key using XChaCha20-Poly1305. A 24-byte nonce is prepended. Only group members can decrypt it.

**The joiner cannot read the capsule.** They carry it opaquely and present it during the knock phase.

### 5.3 Invite Lifecycle

1. **Creator** generates invite, signs it with their identity key, encrypts it with the group key.
2. **Creator** base64url-encodes the encrypted blob into a `vox://` URL.
3. **Joiner** receives URL out-of-band (paste, QR code, messaging app).
4. **Joiner's client** parses URL, extracts the opaque blob. The client cannot decrypt it.
5. **Joiner's client** needs at least one bootstrap peer endpoint. These are embedded in the URL as a small unencrypted hint:

```
vox://join/<encrypted-capsule>?ep=<ip:port>,<ip:port>
```

The `ep` query parameter contains comma-separated bootstrap endpoints in plaintext. This is safe because:
- Endpoints are ephemeral (dynamic IPs, NAT)
- Knowing an endpoint without a valid capsule achieves nothing
- The knock protocol rejects invalid capsules before any state is created

### 5.4 Why Not Encrypt Endpoints?

If endpoints were inside the encrypted capsule, the joiner couldn't read them and wouldn't know where to connect. The endpoints are the minimum information needed to initiate contact. They are not secrets.

---

## 6. WireGuard Handshake Flow

### 6.1 Protocol Overview

The connection establishment has four phases:

```
  Joiner                              Bootstrap Peer
    │                                       │
    │  ── Phase 1: Knock (plain UDP) ──►    │
    │     {joiner_wg_pub, joiner_id_pub,    │
    │      opaque_capsule, password?,       │
    │      timestamp, nonce}                │
    │     encrypted to bootstrap's WG pub   │
    │                                       │
    │  ◄── Phase 2: Knock-Accept ──         │
    │     {bootstrap_wg_pub, status,        │
    │      wg_endpoint, challenge}          │
    │     encrypted to joiner's WG pub      │
    │                                       │
    │  ══ Phase 3: WireGuard Handshake ══   │
    │     Noise_IKpsk2 with known keys      │
    │     (standard WireGuard protocol)     │
    │                                       │
    │  ◄── Phase 4: Admission ──            │
    │     (over WireGuard tunnel)           │
    │     {membership_cert, peer_list,      │
    │      group_state_snapshot}            │
    │                                       │
    │  ── Phase 4b: Ack ──►                 │
    │     {joiner_profile}                  │
    │                                       │
```

### 6.2 Phase 1: Knock

The knock is a single UDP packet sent to the bootstrap peer's endpoint. It is encrypted using NaCl `crypto_box` (X25519 + XSalsa20-Poly1305) to the bootstrap peer's WireGuard public key.

**Knock packet (before encryption):**

| Field | Size | Description |
|---|---|---|
| `protocol_magic` | 4B | `0x564F5801` ("VOX\x01") — identifies Vox knock packets |
| `version` | 1B | Protocol version (1 for MVP) |
| `joiner_wg_pubkey` | 32B | Joiner's ephemeral WireGuard public key |
| `joiner_identity_pubkey` | 32B | Joiner's long-lived Ed25519 public key |
| `capsule_length` | 2B | Length of the opaque invite capsule |
| `capsule` | var | Encrypted invite capsule (opaque to joiner) |
| `password_length` | 1B | Length of password (0 if none) |
| `password` | var | Plaintext password (encrypted in outer layer) |
| `timestamp` | 8B | Unix milliseconds — must be within ±30s of receiver's clock |
| `identity_signature` | 64B | Ed25519 signature over all preceding fields |

**Encrypted with:** `crypto_box(message, nonce, bootstrap_wg_pubkey, joiner_wg_privkey)`

The bootstrap peer's WireGuard public key is obtained from the `ep` hint in the invite URL, paired with the bootstrap public key embedded in the capsule. Since the joiner can't decrypt the capsule, the bootstrap WireGuard public key is also included as a URL parameter:

```
vox://join/<capsule>?ep=<ip:port>&bpk=<base64url-wg-pubkey>
```

### 6.3 Phase 2: Knock-Accept

The bootstrap peer:

1. Decrypts the knock using their WireGuard private key + joiner's WireGuard public key.
2. Validates the timestamp (±30 second window — prevents replay).
3. Decrypts the invite capsule using the group symmetric key.
4. Validates: invite not expired, invite not revoked, invite_id not already used (if single-use).
5. If `password_required` flag is set, verifies BLAKE2b(password) matches `password_hash` in capsule.
6. Validates the creator's signature on the capsule.
7. If all checks pass, sends a Knock-Accept:

| Field | Size | Description |
|---|---|---|
| `protocol_magic` | 4B | `0x564F5802` ("VOX\x02") |
| `status` | 1B | 0=accepted, 1=invalid_capsule, 2=expired, 3=password_wrong, 4=group_full |
| `bootstrap_wg_pubkey` | 32B | Confirming the bootstrap's WG key |
| `wg_listen_port` | 2B | Port for WireGuard handshake |
| `challenge` | 32B | Random challenge for liveness proof |
| `signature` | 64B | Bootstrap peer's Ed25519 identity signature |

**Encrypted with:** `crypto_box(message, nonce, joiner_wg_pubkey, bootstrap_wg_privkey)`

### 6.4 Phase 3: WireGuard Handshake

After Knock-Accept, both peers have each other's WireGuard public keys. A standard WireGuard handshake (Noise_IKpsk2) proceeds. The pre-shared key (PSK) is the group symmetric key — this binds the tunnel to the group.

Implementation options:

| Option | Pros | Cons | Recommendation |
|---|---|---|---|
| **boringtun** (Rust lib via FFI) | Production-grade, cross-platform userspace WG | Rust FFI complexity, ~2MB binary size | **MVP recommendation** |
| **Noise.NET** (managed Noise protocol) | Pure C#, no native deps, fine-grained control | Not a full WireGuard implementation, no keepalive/cookie support | Good for auth-only mode |
| **WireGuardNT** (kernel driver) | Best performance | Windows-only, requires admin, complicates dev | Future optimization |
| **wireguard-go** (Go userspace) | Reference impl | Go runtime overhead, harder FFI | Not recommended |

**MVP recommendation:** Use **boringtun** compiled as a C dynamic library with P/Invoke wrappers. It provides a complete userspace WireGuard implementation callable from C#. For platforms where boringtun isn't available, fall back to Noise.NET for the handshake only.

### 6.5 Phase 4: Admission

Over the now-established WireGuard tunnel (authenticated, encrypted):

**Bootstrap → Joiner:**

| Field | Description |
|---|---|
| `membership_certificate` | Signed statement: "PeerId X is a member of GroupId Y, admitted by PeerId Z at time T" |
| `peer_list` | All current group members: identity pubkey, username#discriminator, WG pubkey, last-known endpoints, online status |
| `group_state_snapshot` | Compressed event log for group reconstruction (members, channel config, recent chat history) |
| `group_symmetric_key` | The group's symmetric key, encrypted to the joiner's identity public key |

**Joiner → Bootstrap:**

| Field | Description |
|---|---|
| `ack` | Confirmation of receipt |
| `joiner_profile` | Username, discriminator, identity pubkey, capabilities |

After admission, the bootstrap peer broadcasts a `MemberJoined` event to all online peers. The joiner begins establishing WebRTC connections to other online peers using the peer list.

### 6.6 Security Properties

| Property | Mechanism |
|---|---|
| Invite cannot grant access alone | Capsule is opaque to joiner; requires online member to decrypt and validate |
| Replay prevention | Timestamp window ±30s; single-use invites tracked by invite_id |
| Man-in-the-middle prevention | Knock is encrypted to bootstrap's WG pubkey; WireGuard handshake is mutually authenticated |
| Forward secrecy | WireGuard keys are ephemeral per-session; identity keys only used for signing |
| No public discoverability | No directory, no DHT, no broadcast. Peers are found only via invite URLs |

---

## 7. WebRTC Integration

### 7.1 Role of WebRTC

After WireGuard authentication, all ongoing communication uses WebRTC:

| Channel | Type | Purpose |
|---|---|---|
| `vox-signaling` | DataChannel (reliable, ordered) | WebRTC offer/answer exchange for new peers, group state events |
| `vox-chat` | DataChannel (reliable, ordered) | Text messages |
| `vox-routing` | DataChannel (reliable, unordered) | Link-state updates, routing table sync |
| `vox-voice` | DataChannel (unreliable, unordered) | Voice frames (Opus) — **not** MediaStream |
| `vox-presence` | DataChannel (reliable, unordered) | Online/offline/away status |

### 7.2 Why DataChannel for Voice (Not MediaStream)?

WebRTC MediaStreams are designed for point-to-point media. Vox requires:

- **Mesh relaying**: a peer must decode, mix (optionally), and re-encode or forward raw Opus frames.
- **Custom routing**: the mesh router decides where frames go, which is impossible with MediaStream's direct path.
- **Multi-source mixing**: each peer mixes N incoming streams locally.

Using an **unreliable, unordered DataChannel** for voice frames gives us the UDP-like semantics we need while inheriting WebRTC's ICE NAT traversal.

### 7.3 Signaling Without Servers

WebRTC requires SDP offer/answer exchange. In Vox, signaling flows through existing connections:

```
Peer A (new)                    Peer B (bootstrap)              Peer C (existing)
    │                                │                               │
    │  [WireGuard tunnel exists]     │  [WebRTC already connected]   │
    │                                │                               │
    │ ─── SDP Offer (for C) ──────►  │                               │
    │     via WG tunnel              │ ─── Forward SDP Offer ──────► │
    │                                │     via vox-signaling DC       │
    │                                │                               │
    │                                │ ◄── SDP Answer (for A) ────── │
    │ ◄── Forward SDP Answer ──────  │                               │
    │                                │                               │
    │ ═══════ WebRTC Direct Connection (ICE) ═══════════════════════► │
    │                                                                 │
```

The WireGuard tunnel with the bootstrap peer serves as the initial signaling channel. Once WebRTC data channels are established with more peers, signaling can be forwarded through any connected peer.

### 7.4 ICE Configuration

```csharp
var iceConfig = new RTCConfiguration
{
    IceServers = new[]
    {
        new RTCIceServer { Urls = new[] { "stun:stun.l.google.com:19302" } },
        new RTCIceServer { Urls = new[] { "stun:stun1.l.google.com:19302" } },
        // No TURN for MVP — accept some NAT types won't work
    },
    IceTransportPolicy = RTCIceTransportPolicy.All,
    BundlePolicy = RTCBundlePolicy.MaxBundle,
};
```

### 7.5 WebRTC Library Selection

| Library | Language | Notes |
|---|---|---|
| **SIPSorcery** | C# (managed) | Mature, pure .NET, DataChannel support. **MVP recommendation.** |
| **webrtc-dotnet** | C# wrapper over libwebrtc | Better media support, but heavier. |
| **libdatachannel** | C (via P/Invoke) | Lightweight, DataChannel-focused. Good alternative. |

**MVP recommendation:** SIPSorcery. It's pure managed .NET, supports DataChannels, and avoids native dependency complexity. Voice goes through DataChannel (not MediaStream), so we don't need libwebrtc's media engine.

---

## 8. Group State Management

### 8.1 Event-Sourced Model

Group state is represented as an append-only log of signed events. Each peer maintains a local copy. State is reconstructed by replaying events in causal order.

### 8.2 Event Structure

```
┌────────────────────────────────────────────┐
│  event_id        : 16 bytes (UUID v7)      │
│  group_id        : 32 bytes                │
│  author          : 32 bytes (identity pub) │
│  lamport_clock   : 8 bytes (uint64)        │
│  parent_ids      : list of event_ids       │
│    count         : 1 byte                  │
│    ids           : count × 16 bytes        │
│  event_type      : 1 byte                  │
│  payload         : variable                │
│  signature       : 64 bytes                │
└────────────────────────────────────────────┘
```

### 8.3 Event Types (MVP)

| Type | Code | Payload |
|---|---|---|
| `MemberJoined` | 0x01 | `{ identity_pubkey, username, discriminator, admitted_by, membership_cert }` |
| `MemberLeft` | 0x02 | `{ identity_pubkey, reason }` |
| `ChatMessage` | 0x03 | `{ message_id, content_utf8, timestamp }` |
| `PresenceChanged` | 0x04 | `{ identity_pubkey, status, since }` |
| `GroupMetadataChanged` | 0x05 | `{ field, old_value, new_value }` |

### 8.4 Consistency Model

- **Causal ordering:** Events reference parent event IDs. A peer does not apply an event until all its parents are present locally.
- **Lamport clocks:** Provide a total order fallback when causal ordering is ambiguous (concurrent events from different peers).
- **Conflict resolution:** For MVP, last-writer-wins (highest Lamport clock) for metadata conflicts. Chat messages are inherently commutative (append-only).
- **Anti-entropy:** When a peer comes online, it requests missing events from connected peers by sending its latest known event IDs. Peers respond with any events the requester is missing.

### 8.5 State Synchronization

```
Peer A (reconnecting)                 Peer B (online)
    │                                      │
    │ ── SyncRequest ──────────────────►   │
    │    { my_latest_event_ids,            │
    │      my_lamport_clock }              │
    │                                      │
    │ ◄── SyncResponse ─────────────────   │
    │    { missing_events[],               │
    │      current_member_list }           │
    │                                      │
```

For MVP with 2-10 users and short chat history, the full event log is small enough to sync in its entirety. No pagination or snapshotting needed yet.

---

## 9. Mesh Routing Algorithm

### 9.1 Goals

- Deliver voice frames from any source to all group members with minimum latency.
- Route around failed or degraded links automatically.
- Prevent routing loops.
- Work for 2-10 peers without excessive overhead.

### 9.2 Topology Management

Each peer maintains:

1. **Neighbor table:** Directly connected peers (WebRTC connections) with measured link metrics.
2. **Link-state database:** Aggregated view of all link metrics in the group (received from all peers).
3. **Routing table:** Computed next-hop for each destination, with primary and backup routes.

### 9.3 Link Quality Metrics

Each peer measures the following for each direct neighbor, using periodic probes (every 1 second):

| Metric | Measurement Method | Range |
|---|---|---|
| RTT | Probe/pong via `vox-routing` DataChannel | 0–5000 ms |
| Jitter | Standard deviation of RTT over 10-sample sliding window | 0–1000 ms |
| Packet loss | Sequence gap detection over 100-packet window | 0–100% |
| Stability | Fraction of successful probes over 60-second window | 0.0–1.0 |
| Capacity | Self-reported: `min(cpu_headroom, bandwidth_headroom)` | 0.0–1.0 |

**Capacity** is computed locally:

```
cpu_headroom = 1.0 - (current_cpu_usage / max_cpu_for_relay)
bandwidth_headroom = 1.0 - (current_bw_usage / estimated_upload_capacity)
capacity = min(cpu_headroom, bandwidth_headroom)
```

### 9.4 Link Cost Function

$$
C(link) = w_r \cdot RTT + w_j \cdot Jitter + w_l \cdot L(loss) + w_s \cdot (1 - Stability) + w_c \cdot (1 - Capacity)
$$

Where:

| Weight | Value | Rationale |
|---|---|---|
| $w_r$ | 1.0 | Baseline: 1ms RTT = 1 cost unit |
| $w_j$ | 2.0 | Jitter is more damaging than steady latency for voice |
| $w_l$ | 50.0 | Multiplied by $L(loss)$ which is exponential |
| $w_s$ | 10.0 | Unstable links should be strongly penalized |
| $w_c$ | 5.0 | Prefer peers with headroom for relaying |

Loss penalty function (exponential to severely penalize any loss):

$$
L(loss) = -\ln(1 - loss\_rate) \times 100
$$

Examples:
- 0% loss → $L = 0$
- 1% loss → $L = 1.005$
- 5% loss → $L = 5.13$
- 10% loss → $L = 10.54$
- 30% loss → $L = 35.67$

A path with 5% packet loss has cost contribution $50 \times 5.13 = 256.5$ — effectively blacklisting it for voice.

### 9.5 Route Computation

**Algorithm:** Modified Dijkstra's shortest path over the link-state database.

```
function ComputeRoutes(self, link_state_db):
    // Standard Dijkstra with our cost function
    dist = { self: 0 }
    prev = { self: null }
    queue = MinHeap()
    queue.push(self, 0)

    while queue is not empty:
        u = queue.pop_min()
        for each neighbor v of u in link_state_db:
            cost = C(link(u, v))
            alt = dist[u] + cost
            if alt < dist.get(v, ∞):
                dist[v] = alt
                prev[v] = u
                queue.push(v, alt)

    // Build routing table
    for each peer p != self:
        primary_next_hop = backtrack(prev, self, p)
        // Compute backup by removing primary edge and re-running
        backup_next_hop = ComputeBackupRoute(self, p, primary_next_hop, link_state_db)
        routing_table[p] = { primary: primary_next_hop, backup: backup_next_hop, cost: dist[p] }
```

Routes are recomputed when:
- A link-state update is received (metric changed > 10%).
- A neighbor connection is established or dropped.
- Periodic recomputation every 10 seconds (consistency check).

For 10 peers with 45 potential edges, Dijkstra runs in microseconds. No performance concern.

### 9.6 Voice Frame Distribution

For voice, we need **multicast**: one speaker's audio must reach all listeners.

**Strategy: Source-rooted multicast tree**

For each active speaker, construct a shortest-path tree from the source to all other peers using the routing table:

```
Speaker A sends to 9 listeners. Routing table says:
  A → B (direct, cost 5)
  A → C (direct, cost 8)
  A → D (via B, cost 12)    // B relays to D
  A → E (via C, cost 15)    // C relays to E
  ...

Resulting fanout:
  A sends to: B, C, F       (first-hop peers)
  B relays to: D, G          (second-hop)
  C relays to: E, H          (second-hop)
  F relays to: I              (second-hop)
```

Each peer examines incoming voice frames and forwards to downstream peers in its relay set. The relay set is computed from the multicast tree.

**Optimization for small groups (N ≤ 5):** Use full mesh. Every peer sends directly to every other peer. No relaying. This eliminates relay latency and complexity for the common case.

### 9.7 Loop Prevention

| Mechanism | Description |
|---|---|
| **Packet ID** | 64-bit unique ID per voice frame. Each peer maintains a seen-set (LRU cache, 8192 entries, 5-second TTL). Duplicate frames are dropped silently. |
| **TTL** | Initial TTL = `min(N, 7)` where N is group size. Decremented at each hop. Frame dropped when TTL = 0. |
| **Path recording** | Each relay appends its PeerId to the relay path in the frame header. A peer never relays a frame that already contains its own ID. |
| **Source filtering** | A peer never relays its own frames back to itself. |

### 9.8 Failover

```
Normal: A ──► B ──► D
                         B goes offline
Failover: A ──► C ──► D  (backup route activated within 2 seconds)
```

**Detection:** If 3 consecutive probes fail (3 seconds), the link is marked DOWN. The backup route is activated immediately via local routing table swap. A link-state update is broadcast to all peers.

**Recovery:** When the link comes back, probes resume. After 5 consecutive successful probes, the link is marked UP and new routes are computed. Hysteresis prevents flapping.

---

## 10. Packet Structures (Wire Format)

All packets sent over WebRTC DataChannels share a common header. Binary encoding, little-endian.

### 10.1 Common Header (15 bytes)

```
Offset  Size  Field
──────  ────  ─────
0       1     packet_type
1       4     payload_length (excludes header)
5       8     packet_id (unique, monotonic per sender)
13      1     ttl
14      1     flags
              bit 0: compressed (zstd)
              bit 1: fragmented
              bit 2: requires_ack
              bits 3-7: reserved
```

### 10.2 Packet Type Registry

| Code | Name | Channel | Reliability |
|---|---|---|---|
| `0x01` | Knock | Raw UDP | N/A |
| `0x02` | KnockAccept | Raw UDP | N/A |
| `0x03` | Admission | WireGuard | Reliable |
| `0x04` | AdmissionAck | WireGuard | Reliable |
| `0x10` | ChatMessage | `vox-chat` DC | Reliable, ordered |
| `0x11` | ChatAck | `vox-chat` DC | Reliable, ordered |
| `0x20` | VoiceFrame | `vox-voice` DC | Unreliable, unordered |
| `0x21` | RelayFrame | `vox-voice` DC | Unreliable, unordered |
| `0x30` | PresenceUpdate | `vox-presence` DC | Reliable, unordered |
| `0x40` | LinkStateUpdate | `vox-routing` DC | Reliable, unordered |
| `0x41` | RoutingProbe | `vox-routing` DC | Unreliable |
| `0x42` | RoutingPong | `vox-routing` DC | Unreliable |
| `0x50` | PeerListSync | `vox-signaling` DC | Reliable, ordered |
| `0x51` | SdpOffer | `vox-signaling` DC | Reliable, ordered |
| `0x52` | SdpAnswer | `vox-signaling` DC | Reliable, ordered |
| `0x53` | IceCandidate | `vox-signaling` DC | Reliable, ordered |
| `0x60` | GroupStateSync | `vox-signaling` DC | Reliable, ordered |
| `0x61` | GroupEvent | `vox-signaling` DC | Reliable, ordered |

### 10.3 ChatMessage (0x10)

```
Offset  Size  Field
──────  ────  ─────
0       15    [common header]
15      32    sender_identity (Ed25519 pubkey)
47      32    group_id
79      16    message_id (UUID v7)
95      8     timestamp (Unix ms)
103     8     lamport_clock
111     1     parent_count
112     N×16  parent_event_ids
var     4     content_length
var     X     content_utf8
var     64    signature (Ed25519, over bytes 15..end-64)
```

**Maximum content size:** 4000 bytes UTF-8 (enforced at application layer).

### 10.4 VoiceFrame (0x20)

Optimized for minimal overhead. Every millisecond matters.

```
Offset  Size  Field
──────  ────  ─────
0       1     packet_type (0x20)
1       4     sequence_number (wrapping uint32)
5       8     timestamp_us (microseconds since epoch, for jitter buffer)
13      32    sender_identity
45      1     codec_flags
              bits 0-3: codec (0=Opus)
              bit 4: DTX (silence frame)
              bit 5: FEC present
              bits 6-7: reserved
46      1     channel_id (voice channel index)
47      2     frame_length
49      X     opus_payload (typically 40-120 bytes for 20ms Opus @ 32-64kbps)
```

**Total overhead per voice frame:** 49 bytes header + Opus payload.
**At 50 frames/sec (20ms):** 49 × 50 = 2450 bytes/sec overhead = ~20 kbps. Acceptable.

Note: VoiceFrame uses a **minimal header** (no common header) to minimize per-frame overhead. The `packet_id` from the common header is replaced by `sequence_number` for jitter buffer ordering. TTL and flags are omitted for direct-path frames.

### 10.5 RelayFrame (0x21)

When a voice frame must be relayed through intermediate peers:

```
Offset  Size  Field
──────  ────  ─────
0       15    [common header] (packet_type=0x21, TTL decremented)
15      32    original_sender
47      32    final_destination (or 0xFF..FF for multicast)
79      1     hop_count
80      N×32  relay_path (each hop's identity, for loop prevention)
var     2     inner_length
var     X     inner_packet (complete VoiceFrame)
```

The relay peer:
1. Checks `packet_id` against seen-set → drop if duplicate.
2. Checks TTL → drop if 0.
3. Checks relay_path → drop if own identity already present.
4. Decrements TTL, appends own identity to relay_path.
5. Looks up next-hop(s) in multicast relay set.
6. Forwards to each next-hop.

### 10.6 LinkStateUpdate (0x40)

```
Offset  Size  Field
──────  ────  ─────
0       15    [common header]
15      32    reporter_identity
47      8     timestamp (Unix ms)
55      8     lamport_clock
63      1     link_count
64      N×41  links[]
              Each link:
                peer_identity  : 32 bytes
                rtt_ms         : 2 bytes (uint16)
                jitter_ms      : 2 bytes (uint16)
                loss_percent   : 1 byte  (0-100)
                stability_pct  : 1 byte  (0-100)
                capacity_pct   : 1 byte  (0-100)
                status         : 1 byte  (0=down, 1=up, 2=degraded)
                reserved       : 1 byte
var     64    signature
```

### 10.7 PresenceUpdate (0x30)

```
Offset  Size  Field
──────  ────  ─────
0       15    [common header]
15      32    identity
47      1     status (0=offline, 1=online, 2=away, 3=dnd)
48      8     since (Unix ms)
56      64    signature
```

### 10.8 PeerListSync (0x50)

Sent during initial sync and when topology changes.

```
Offset  Size  Field
──────  ────  ─────
0       15    [common header]
15      32    group_id
47      2     peer_count
49      N×var peers[]
              Each peer:
                identity_pubkey  : 32 bytes
                wg_pubkey        : 32 bytes
                username_len     : 1 byte
                username         : var bytes (UTF-8)
                discriminator    : 2 bytes
                endpoint_count   : 1 byte
                endpoints[]      : each 6 bytes (4B IPv4 + 2B port)
                status           : 1 byte
                capabilities     : 2 bytes (bitfield: voice, relay, etc.)
var     64    signature
```

---

## 11. Voice Pipeline

### 11.1 Pipeline Architecture

```
┌──────────┐   ┌─────────┐   ┌──────────┐   ┌───────────┐   ┌──────────┐
│  Capture │──►│ PTT/VAD │──►│ Denoise  │──►│  Encode   │──►│  Route   │
│  (Mic)   │   │  Gate   │   │ (RNNoise)│   │  (Opus)   │   │  (Mesh)  │
└──────────┘   └─────────┘   └──────────┘   └───────────┘   └──────────┘
                                                                  │
                                                    ┌─────────────┘
                                                    ▼
┌──────────┐   ┌─────────┐   ┌──────────┐   ┌───────────┐
│ Playback │◄──│  Mixer  │◄──│  Decode  │◄──│  Jitter   │
│ (Speaker)│   │ (N→1)   │   │  (Opus)  │   │  Buffer   │
└──────────┘   └─────────┘   └──────────┘   └───────────┘
```

### 11.2 Audio Parameters

| Parameter | Value | Rationale |
|---|---|---|
| Sample rate | 48000 Hz | Opus native, maximum quality |
| Frame duration | 20 ms | Standard VoIP frame — balance of latency and efficiency |
| Samples per frame | 960 | 48000 × 0.020 |
| Channels | 1 (mono) | Voice doesn't benefit from stereo |
| Bit depth | 16-bit PCM | Input from mic, output to speaker |
| Opus bitrate | 32 kbps | OPUS_APPLICATION_VOIP mode, excellent for speech |
| Opus complexity | 5 | Balance of quality and CPU |
| Opus FEC | Enabled | In-band forward error correction |
| Opus DTX | Enabled | Discontinuous transmission — near-zero bitrate during silence |

### 11.3 Capture Pipeline Detail

```csharp
// Conceptual pipeline — actual implementation uses lock-free ring buffers

while (!cancellation.IsCancellationRequested)
{
    // 1. Capture 20ms of audio from mic
    ReadOnlySpan<short> pcm = audioCapture.Read(samplesPerFrame: 960);

    // 2. PTT gate — if push-to-talk is not active, skip
    if (pttMode && !pttActive)
        continue;

    // 3. Noise suppression (RNNoise operates on float32 frames of 480 samples at 48kHz)
    //    RNNoise native frame size is 480 (10ms). Process two sub-frames.
    Span<float> floatPcm = ConvertToFloat(pcm);
    float vadProb1 = rnnoise.Process(floatPcm[..480]);
    float vadProb2 = rnnoise.Process(floatPcm[480..]);

    // 4. Optional VAD gate (if not PTT mode)
    if (!pttMode && vadProb1 < 0.5f && vadProb2 < 0.5f)
        continue; // Silence — don't transmit

    // 5. Convert back to int16 for Opus
    Span<short> denoised = ConvertToInt16(floatPcm);

    // 6. Opus encode
    Span<byte> encoded = stackalloc byte[MaxOpusFrameSize]; // 256 bytes max
    int encodedLen = opusEncoder.Encode(denoised, encoded);

    // 7. Build VoiceFrame packet
    var frame = VoiceFrame.Create(
        sequence: nextSequence++,
        timestamp: Stopwatch.GetTimestamp(),
        sender: localIdentity,
        channelId: currentVoiceChannel,
        opusData: encoded[..encodedLen]
    );

    // 8. Send to mesh router
    meshRouter.Distribute(frame);
}
```

### 11.4 Jitter Buffer

**Type:** Adaptive jitter buffer with configurable target latency.

| Parameter | Value |
|---|---|
| Minimum buffer | 20 ms (1 frame) |
| Initial target | 60 ms (3 frames) |
| Maximum buffer | 200 ms (10 frames) |
| Adaptation rate | ±5 ms per second |

**Algorithm:**

```
On frame arrival:
  if frame.sequence in received_set: drop (duplicate)
  insert into priority queue ordered by sequence
  update jitter estimate: jitter = 0.9 * jitter + 0.1 * abs(actual_arrival - expected_arrival)
  target_delay = max(MIN_DELAY, min(2 * jitter, MAX_DELAY))

On playback tick (every 20ms):
  if queue has frame with sequence == next_expected:
    output frame, next_expected++
  else if queue has frames but gap in sequence:
    if oldest frame has waited > target_delay:
      // Late frame — skip gap, output next available
      next_expected = oldest_frame.sequence
      output oldest_frame, next_expected++
    else:
      // Output silence (PLC) — Opus decoder generates comfort noise
      output opus_decode(null) // null input triggers PLC
  else:
    // Buffer underrun — output silence
    output silence
```

### 11.5 Audio Mixing

Each peer receives N-1 decoded PCM streams. They must be mixed to a single output.

```csharp
void MixAndPlay(ReadOnlySpan<short>[] decodedStreams, Span<short> output)
{
    // Sum with saturation (avoid clipping)
    for (int i = 0; i < output.Length; i++)
    {
        int sum = 0;
        for (int s = 0; s < decodedStreams.Length; s++)
        {
            sum += decodedStreams[s][i];
        }
        output[i] = (short)Math.Clamp(sum, short.MinValue, short.MaxValue);
    }
}
```

For MVP, simple additive mixing with clamping is sufficient. AGC (automatic gain control) can be added later.

### 11.6 Mic Device Selection

Enumerate audio devices via platform API. Expose through `IAudioDeviceService`:

```csharp
public interface IAudioDeviceService
{
    IReadOnlyList<AudioDevice> GetCaptureDevices();
    IReadOnlyList<AudioDevice> GetPlaybackDevices();
    AudioDevice GetDefaultCaptureDevice();
    AudioDevice GetDefaultPlaybackDevice();
    void SetCaptureDevice(AudioDevice device);
    void SetPlaybackDevice(AudioDevice device);
    event Action DevicesChanged;
}
```

---

## 12. .NET Abstractions

### 12.1 Core Types

```csharp
namespace Vox.Core;

// === Identity ===

public readonly record struct PeerId(byte[] PublicKey)
{
    public string ToHex() => Convert.ToHexString(PublicKey);
    public bool Equals(PeerId other) => PublicKey.AsSpan().SequenceEqual(other.PublicKey);
    public override int GetHashCode() => BitConverter.ToInt32(PublicKey, 0);
}

public readonly record struct GroupId(byte[] Id)
{
    public string ToHex() => Convert.ToHexString(Id);
}

public sealed record LocalIdentity(
    string Username,
    ushort Discriminator,
    byte[] SigningPublicKey,    // Ed25519 — 32 bytes
    byte[] SigningPrivateKey,   // Ed25519 — 64 bytes
    byte[] EncryptionPublicKey, // X25519  — 32 bytes
    byte[] EncryptionPrivateKey // X25519  — 32 bytes
)
{
    public PeerId PeerId => new(SigningPublicKey);
    public string DisplayName => $"{Username}#{Discriminator:D4}";
}

public sealed record PeerInfo(
    PeerId Id,
    string Username,
    ushort Discriminator,
    byte[] WireGuardPublicKey,
    List<IPEndPoint> Endpoints,
    PeerStatus Status,
    PeerCapabilities Capabilities
);

public enum PeerStatus : byte { Offline = 0, Online = 1, Away = 2, DoNotDisturb = 3 }

[Flags]
public enum PeerCapabilities : ushort
{
    None = 0,
    Voice = 1 << 0,
    Relay = 1 << 1,
    HighBandwidth = 1 << 2,
}

// === Group ===

public sealed record GroupInfo(
    GroupId Id,
    string Name,
    byte[] SymmetricKey,       // XChaCha20-Poly1305 key — 32 bytes
    PeerId Creator,
    DateTimeOffset CreatedAt,
    List<PeerInfo> Members
);

// === Invite ===

public sealed record InviteCapsule(
    Guid InviteId,
    GroupId GroupId,
    PeerId Creator,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    InviteFlags Flags,
    byte[]? PasswordHash,      // BLAKE2b — 32 bytes, null if no password
    List<BootstrapPeer> BootstrapPeers
);

[Flags]
public enum InviteFlags : byte
{
    None = 0,
    PasswordRequired = 1 << 0,
    SingleUse = 1 << 1,
}

public sealed record BootstrapPeer(
    byte[] WireGuardPublicKey,
    IPEndPoint Endpoint
);

public sealed record InviteUrl(string Url)
{
    // vox://join/<base64url-capsule>?ep=<ip:port>&bpk=<base64url-wg-pubkey>
    public static InviteUrl Create(byte[] encryptedCapsule, List<BootstrapPeer> bootstrapPeers) { ... }
    public static (byte[] Capsule, List<(IPEndPoint Ep, byte[] WgPub)> Bootstraps) Parse(string url) { ... }
}
```

### 12.2 Service Interfaces

```csharp
namespace Vox.Core.Abstractions;

// === Identity Service ===

public interface IIdentityService
{
    LocalIdentity GetOrCreateIdentity();
    byte[] Sign(ReadOnlySpan<byte> data);
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
}

// === Crypto Service ===

public interface ICryptoService
{
    byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key);
    byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key);
    byte[] Box(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> senderPrivateKey);
    byte[] BoxOpen(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> senderPublicKey, ReadOnlySpan<byte> recipientPrivateKey);
    byte[] Hash(ReadOnlySpan<byte> data); // BLAKE2b
    (byte[] PublicKey, byte[] PrivateKey) GenerateEd25519Keypair();
    (byte[] PublicKey, byte[] PrivateKey) GenerateX25519Keypair();
}

// === Group Service ===

public interface IGroupService
{
    Task<GroupInfo> CreateGroupAsync(string name);
    Task<InviteUrl> CreateInviteAsync(GroupId groupId, InviteOptions? options = null);
    Task<JoinResult> JoinViaInviteAsync(InviteUrl invite, string? password = null);
    Task LeaveGroupAsync(GroupId groupId);
    IReadOnlyList<GroupInfo> GetJoinedGroups();
    IObservable<GroupEvent> GroupEvents { get; }
}

public sealed record InviteOptions(
    TimeSpan? Expiry = null,        // Default: 24 hours
    bool SingleUse = false,
    string? Password = null
);

public sealed record JoinResult(bool Success, string? Error, GroupInfo? Group);

// === Transport Service ===

public interface ITransportService
{
    Task<bool> ConnectToPeerAsync(PeerInfo peer);
    Task DisconnectFromPeerAsync(PeerId peerId);
    Task SendAsync(PeerId destination, byte[] data, DataChannelName channel);
    Task BroadcastAsync(GroupId group, byte[] data, DataChannelName channel);
    IObservable<IncomingMessage> IncomingMessages { get; }
    IReadOnlyDictionary<PeerId, PeerConnectionState> ConnectedPeers { get; }
}

public readonly record struct DataChannelName(string Value)
{
    public static readonly DataChannelName Signaling = new("vox-signaling");
    public static readonly DataChannelName Chat = new("vox-chat");
    public static readonly DataChannelName Voice = new("vox-voice");
    public static readonly DataChannelName Routing = new("vox-routing");
    public static readonly DataChannelName Presence = new("vox-presence");
}

public sealed record IncomingMessage(PeerId Sender, DataChannelName Channel, byte[] Data);

// === Mesh Router ===

public interface IMeshRouter
{
    PeerId? GetNextHop(PeerId destination);
    IReadOnlyList<PeerId> GetMulticastRelaySet(PeerId source);
    void UpdateLinkMetrics(PeerId peer, LinkMetrics metrics);
    void OnPeerConnected(PeerId peer);
    void OnPeerDisconnected(PeerId peer);
    IReadOnlyDictionary<PeerId, RouteEntry> GetRoutingTable();
    IObservable<RoutingTableChanged> RoutingChanges { get; }
    void Distribute(VoiceFrame frame); // Multicast voice to appropriate next-hops
}

public sealed record LinkMetrics(
    ushort RttMs,
    ushort JitterMs,
    byte LossPercent,
    byte StabilityPercent,
    byte CapacityPercent
);

public sealed record RouteEntry(
    PeerId Destination,
    PeerId PrimaryNextHop,
    PeerId? BackupNextHop,
    double Cost,
    int HopCount
);

// === Voice Pipeline ===

public interface IVoicePipeline
{
    Task StartAsync(VoiceSessionConfig config);
    Task StopAsync();
    bool IsSpeaking { get; }
    void SetPushToTalk(bool pressed);
    void SetMicDevice(AudioDevice device);
    void SetSpeakerDevice(AudioDevice device);
    void SetNoiseSuppression(bool enabled);
    IObservable<VoicePipelineStats> Stats { get; } // For UI: current bitrate, latency, etc.
}

public sealed record VoiceSessionConfig(
    GroupId GroupId,
    byte ChannelId,
    bool PushToTalk,
    bool NoiseSuppression,
    int OpusBitrate = 32000
);

// === WireGuard Service ===

public interface IWireGuardService
{
    Task<KnockResult> SendKnockAsync(IPEndPoint endpoint, byte[] bootstrapWgPubKey, byte[] capsule, string? password);
    void ListenForKnocks(int port, Func<KnockRequest, Task<KnockResponse>> handler);
    Task<WireGuardTunnel> EstablishTunnelAsync(byte[] peerWgPubKey, IPEndPoint peerEndpoint, byte[] psk);
    void StopListening();
}

public sealed record KnockResult(
    bool Accepted,
    byte StatusCode,
    byte[]? BootstrapWgPubKey,
    IPEndPoint? WgEndpoint,
    byte[]? Challenge
);

public sealed record KnockRequest(
    byte[] JoinerWgPubKey,
    byte[] JoinerIdentityPubKey,
    byte[] Capsule,
    string? Password,
    long Timestamp,
    byte[] Signature,
    IPEndPoint RemoteEndpoint
);

public sealed record WireGuardTunnel(
    PeerId RemotePeerId,
    byte[] RemoteWgPubKey,
    IPEndPoint RemoteEndpoint,
    Stream ReadStream,
    Stream WriteStream
) : IAsyncDisposable;

// === Chat Service ===

public interface IChatService
{
    Task SendMessageAsync(GroupId groupId, string content);
    IObservable<ChatMessageReceived> IncomingMessages { get; }
    Task<IReadOnlyList<ChatMessageRecord>> GetHistoryAsync(GroupId groupId, int limit = 100, Guid? before = null);
}

public sealed record ChatMessageRecord(
    Guid MessageId,
    GroupId GroupId,
    PeerId Author,
    string AuthorDisplayName,
    string Content,
    DateTimeOffset Timestamp,
    ulong LamportClock,
    bool Verified // Signature check passed
);

// === Presence Service ===

public interface IPresenceService
{
    IObservable<PresenceChanged> PresenceChanges { get; }
    PeerStatus GetStatus(PeerId peer);
    IReadOnlyDictionary<PeerId, PeerStatus> GetGroupPresence(GroupId groupId);
    Task SetStatusAsync(PeerStatus status);
}

public sealed record PresenceChanged(PeerId Peer, PeerStatus OldStatus, PeerStatus NewStatus);
```

### 12.3 Packet Serialization

Use a zero-allocation serialization approach with `Span<byte>` and `IBufferWriter<byte>`:

```csharp
namespace Vox.Core.Protocol;

public interface IPacketSerializer<T> where T : struct
{
    int Serialize(in T packet, Span<byte> buffer);
    T Deserialize(ReadOnlySpan<byte> buffer);
    int GetSerializedSize(in T packet);
}

// Example for VoiceFrame:
public readonly struct VoiceFramePacket
{
    public readonly uint Sequence;
    public readonly long TimestampUs;
    public readonly PeerId Sender;
    public readonly byte CodecFlags;
    public readonly byte ChannelId;
    public readonly ReadOnlyMemory<byte> OpusData;

    // No heap allocation during serialize/deserialize in hot path
}

public sealed class VoiceFrameSerializer : IPacketSerializer<VoiceFramePacket>
{
    public int Serialize(in VoiceFramePacket packet, Span<byte> buffer)
    {
        int offset = 0;
        buffer[offset++] = 0x20; // packet_type
        BinaryPrimitives.WriteUInt32LittleEndian(buffer[offset..], packet.Sequence); offset += 4;
        BinaryPrimitives.WriteInt64LittleEndian(buffer[offset..], packet.TimestampUs); offset += 8;
        packet.Sender.PublicKey.AsSpan().CopyTo(buffer[offset..]); offset += 32;
        buffer[offset++] = packet.CodecFlags;
        buffer[offset++] = packet.ChannelId;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer[offset..], (ushort)packet.OpusData.Length); offset += 2;
        packet.OpusData.Span.CopyTo(buffer[offset..]);
        offset += packet.OpusData.Length;
        return offset;
    }

    // ... Deserialize symmetrically
}
```

---

## 13. Project Folder Structure

```
Vox/
├── Vox.slnx                          # Solution file
│
├── src/
│   ├── Vox.Core/                      # Core library (netstandard2.1 or net10.0)
│   │   ├── Vox.Core.csproj
│   │   ├── Identity/
│   │   │   ├── LocalIdentity.cs
│   │   │   ├── PeerId.cs
│   │   │   ├── IIdentityService.cs
│   │   │   └── IdentityService.cs
│   │   ├── Crypto/
│   │   │   ├── ICryptoService.cs
│   │   │   ├── LibsodiumCryptoService.cs
│   │   │   └── Interop/
│   │   │       └── Libsodium.cs        # P/Invoke declarations
│   │   ├── Protocol/
│   │   │   ├── PacketTypes.cs           # Enum + constants
│   │   │   ├── CommonHeader.cs
│   │   │   ├── VoiceFramePacket.cs
│   │   │   ├── RelayFramePacket.cs
│   │   │   ├── ChatMessagePacket.cs
│   │   │   ├── PresencePacket.cs
│   │   │   ├── LinkStatePacket.cs
│   │   │   ├── PeerListPacket.cs
│   │   │   └── Serialization/
│   │   │       ├── IPacketSerializer.cs
│   │   │       ├── VoiceFrameSerializer.cs
│   │   │       ├── ChatMessageSerializer.cs
│   │   │       └── ...
│   │   ├── Groups/
│   │   │   ├── GroupId.cs
│   │   │   ├── GroupInfo.cs
│   │   │   ├── InviteCapsule.cs
│   │   │   ├── InviteUrl.cs
│   │   │   └── MembershipCertificate.cs
│   │   ├── Events/
│   │   │   ├── GroupEvent.cs
│   │   │   ├── GroupEventTypes.cs
│   │   │   └── LamportClock.cs
│   │   └── Configuration/
│   │       └── VoxConfig.cs
│   │
│   ├── Vox.Network/                   # Networking library
│   │   ├── Vox.Network.csproj
│   │   ├── WireGuard/
│   │   │   ├── IWireGuardService.cs
│   │   │   ├── WireGuardService.cs
│   │   │   ├── KnockProtocol.cs
│   │   │   ├── KnockListener.cs
│   │   │   └── Interop/
│   │   │       └── Boringtun.cs        # P/Invoke to boringtun
│   │   ├── WebRtc/
│   │   │   ├── WebRtcSessionManager.cs
│   │   │   ├── DataChannelManager.cs
│   │   │   ├── IceConfiguration.cs
│   │   │   └── SignalingRelay.cs
│   │   ├── Transport/
│   │   │   ├── ITransportService.cs
│   │   │   ├── TransportService.cs
│   │   │   └── ConnectionPool.cs
│   │   ├── Routing/
│   │   │   ├── IMeshRouter.cs
│   │   │   ├── MeshRouter.cs
│   │   │   ├── LinkStateDatabase.cs
│   │   │   ├── RouteComputer.cs        # Dijkstra implementation
│   │   │   ├── ProbeService.cs
│   │   │   ├── SeenPacketCache.cs
│   │   │   └── MulticastTreeBuilder.cs
│   │   └── Nat/
│   │       ├── StunClient.cs
│   │       └── EndpointDiscovery.cs
│   │
│   ├── Vox.Voice/                     # Voice pipeline
│   │   ├── Vox.Voice.csproj
│   │   ├── Capture/
│   │   │   ├── IAudioCaptureService.cs
│   │   │   ├── AudioCaptureService.cs   # Platform-specific via DI
│   │   │   └── CaptureRingBuffer.cs
│   │   ├── Codec/
│   │   │   ├── IOpusCodec.cs
│   │   │   ├── OpusEncoder.cs
│   │   │   ├── OpusDecoder.cs
│   │   │   └── Interop/
│   │   │       └── OpusNative.cs        # P/Invoke to libopus
│   │   ├── Processing/
│   │   │   ├── INoiseSuppressionService.cs
│   │   │   ├── RnnoiseProcessor.cs
│   │   │   └── Interop/
│   │   │       └── RnnoiseNative.cs     # P/Invoke to librnnoise
│   │   ├── Jitter/
│   │   │   ├── AdaptiveJitterBuffer.cs
│   │   │   └── JitterEstimator.cs
│   │   ├── Mixing/
│   │   │   └── AudioMixer.cs
│   │   ├── Playback/
│   │   │   ├── IAudioPlaybackService.cs
│   │   │   ├── AudioPlaybackService.cs
│   │   │   └── PlaybackRingBuffer.cs
│   │   ├── Pipeline/
│   │   │   ├── IVoicePipeline.cs
│   │   │   ├── VoicePipeline.cs         # Orchestrates capture→encode→send + receive→decode→mix→play
│   │   │   └── VoicePipelineStats.cs
│   │   └── Devices/
│   │       ├── IAudioDeviceService.cs
│   │       └── AudioDevice.cs
│   │
│   ├── Vox.Chat/                      # Chat module
│   │   ├── Vox.Chat.csproj
│   │   ├── IChatService.cs
│   │   ├── ChatService.cs
│   │   ├── MessageStore.cs              # SQLite-backed
│   │   ├── MessageDeduplicator.cs
│   │   └── ChatMessageRecord.cs
│   │
│   └── Vox.App/                       # MAUI + Blazor Hybrid app
│       ├── Vox.App.csproj
│       ├── MauiProgram.cs               # DI composition root
│       ├── App.xaml / App.xaml.cs
│       ├── AppShell.xaml / AppShell.xaml.cs
│       ├── MainPage.xaml / MainPage.xaml.cs
│       ├── Services/
│       │   ├── AppLifecycleService.cs
│       │   ├── GroupStateService.cs      # Manages group state for UI
│       │   └── NavigationService.cs
│       ├── ViewModels/
│       │   ├── MainViewModel.cs
│       │   ├── GroupViewModel.cs
│       │   ├── ChatViewModel.cs
│       │   ├── VoiceViewModel.cs
│       │   ├── SettingsViewModel.cs
│       │   └── JoinViewModel.cs
│       ├── Components/                  # Blazor components
│       │   ├── Layout/
│       │   │   ├── AppLayout.razor
│       │   │   ├── Sidebar.razor
│       │   │   └── TopBar.razor
│       │   ├── Groups/
│       │   │   ├── GroupList.razor
│       │   │   ├── GroupPanel.razor
│       │   │   ├── CreateGroupDialog.razor
│       │   │   └── JoinGroupDialog.razor
│       │   ├── Chat/
│       │   │   ├── ChatPanel.razor
│       │   │   ├── MessageBubble.razor
│       │   │   └── ChatInput.razor
│       │   ├── Voice/
│       │   │   ├── VoicePanel.razor
│       │   │   ├── VoiceControls.razor
│       │   │   ├── MicSelector.razor
│       │   │   └── PeerVoiceIndicator.razor
│       │   ├── Presence/
│       │   │   ├── MemberList.razor
│       │   │   └── StatusIndicator.razor
│       │   └── Settings/
│       │       ├── SettingsPanel.razor
│       │       └── AudioSettings.razor
│       ├── wwwroot/
│       │   ├── css/
│       │   │   ├── app.css              # Tailwind output
│       │   │   └── tailwind.config.js
│       │   ├── index.html
│       │   └── js/
│       │       └── interop.js           # Minimal JS interop if needed
│       ├── Platforms/
│       │   ├── Android/
│       │   ├── iOS/
│       │   ├── MacCatalyst/
│       │   └── Windows/
│       └── Resources/
│           ├── AppIcon/
│           ├── Fonts/
│           ├── Images/
│           └── Splash/
│
├── tests/
│   ├── Vox.Core.Tests/
│   ├── Vox.Network.Tests/
│   ├── Vox.Voice.Tests/
│   ├── Vox.Chat.Tests/
│   └── Vox.Integration.Tests/
│
├── native/                            # Native library build scripts
│   ├── boringtun/                     # Rust build for WireGuard
│   ├── opus/                          # Opus build (or NuGet)
│   └── rnnoise/                       # RNNoise build
│
└── docs/
    ├── ARCHITECTURE.md                # This document
    └── PROTOCOL.md                    # Wire protocol reference
```

---

## 14. Threading & Concurrency Model

### 14.1 Thread Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Vox Process                              │
│                                                                 │
│  ┌──────────────┐  UI thread. Blazor rendering, user input.     │
│  │  UI Thread   │  NEVER block. NEVER do crypto, I/O,           │
│  │  (MAUI/STA)  │  or encoding on this thread.                  │
│  └──────┬───────┘                                               │
│         │ Dispatch via InvokeAsync                               │
│         ▼                                                       │
│  ┌──────────────┐  Async I/O for all network operations.        │
│  │  ThreadPool  │  Socket reads, WebRTC events, state sync.     │
│  │  (async/     │  Managed by .NET ThreadPool.                  │
│  │   await)     │  Target: ≤4 threads active concurrently.      │
│  └──────────────┘                                               │
│                                                                 │
│  ┌──────────────┐  Dedicated real-time thread.                  │
│  │  Voice       │  Priority: AboveNormal.                       │
│  │  Capture     │  Tight loop: read mic → denoise → encode →   │
│  │  Thread      │  write to Channel<VoiceFrame>.                │
│  └──────────────┘  Pinned to one core if possible.              │
│                                                                 │
│  ┌──────────────┐  Dedicated real-time thread.                  │
│  │  Voice       │  Priority: AboveNormal.                       │
│  │  Playback    │  Tight loop: read from Channel<DecodedAudio>  │
│  │  Thread      │  → mix → write to speaker.                    │
│  └──────────────┘                                               │
│                                                                 │
│  ┌──────────────┐  Periodic: probe peers, compute routes,       │
│  │  Routing     │  broadcast link-state. Timer-based on          │
│  │  Timer       │  ThreadPool (1-second interval).               │
│  └──────────────┘                                               │
│                                                                 │
│  ┌──────────────┐  Receives encoded voice from transport,       │
│  │  Voice       │  decodes (Opus), manages jitter buffers,      │
│  │  Receive     │  feeds decoded audio to playback thread.       │
│  │  (ThreadPool)│  Uses async await on Channel<IncomingVoice>.   │
│  └──────────────┘                                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 14.2 Thread Synchronization

| Boundary | Mechanism | Rationale |
|---|---|---|
| Capture → Encode → Send | `Channel<VoiceFrame>` (bounded, 10) | Backpressure: if send path is slow, drop oldest. Never block capture. |
| Receive → Decode → Playback | `Channel<DecodedAudio>` (bounded, 20) | Jitter buffer is in the receive pipeline. |
| Network → Application | `Channel<IncomingMessage>` (unbounded) | Reliable channels need backpressure at the transport level. |
| Any → UI | `InvokeAsync` / `IDispatcher` | MAUI dispatcher for UI updates. |
| Routing updates | `ReaderWriterLockSlim` on routing table | Reads are hot-path (every voice frame), writes are rare (topology change). |
| Seen-packet cache | `ConcurrentDictionary<long, byte>` | Lock-free; eviction via periodic sweep. |

### 14.3 Lock-Free Audio Data Structures

The voice capture and playback paths must **never allocate on the managed heap** in the hot loop. Strategies:

```csharp
// Ring buffer for audio samples — pre-allocated, lock-free SPSC
public sealed class SpscRingBuffer<T> where T : unmanaged
{
    private readonly T[] _buffer;
    private volatile int _readPos;
    private volatile int _writePos;

    public SpscRingBuffer(int capacity) => _buffer = new T[capacity];

    public bool TryWrite(ReadOnlySpan<T> data) { ... } // Returns false if full
    public int Read(Span<T> output) { ... } // Returns samples read
}

// Object pool for VoiceFrame packets
public sealed class VoiceFramePool
{
    private readonly ConcurrentBag<byte[]> _pool = new();
    private const int BufferSize = 512; // Max voice frame size

    public byte[] Rent() => _pool.TryTake(out var buf) ? buf : new byte[BufferSize];
    public void Return(byte[] buf) => _pool.Add(buf);
}
```

### 14.4 Cancellation Strategy

All long-running operations accept `CancellationToken`. The app lifecycle manages a root `CancellationTokenSource`:

```csharp
public sealed class AppLifecycleService : IDisposable
{
    private readonly CancellationTokenSource _appCts = new();

    public CancellationToken AppStopping => _appCts.Token;

    // Called by MAUI on app close / background
    public void RequestShutdown()
    {
        _appCts.Cancel();
        // Voice pipeline stops, network connections close, state is persisted
    }
}
```

### 14.5 DI Service Lifetimes

| Service | Lifetime | Rationale |
|---|---|---|
| `IIdentityService` | Singleton | One identity per app instance |
| `ICryptoService` | Singleton | Stateless |
| `IGroupService` | Singleton | Manages all groups |
| `ITransportService` | Singleton | One transport layer |
| `IMeshRouter` | Singleton | One router per app |
| `IWireGuardService` | Singleton | One listener |
| `IVoicePipeline` | Scoped (per active voice session) | Created when joining a voice channel, disposed when leaving |
| `IChatService` | Singleton | Handles all group chats |
| `IPresenceService` | Singleton | Manages presence for all peers |
| `IAudioDeviceService` | Singleton | System audio device enumeration |

---

## 15. Performance Risks & Mitigations

### 15.1 Critical Risks

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| 1 | **GC pauses on voice thread** | HIGH | Use `stackalloc`, object pools, `Span<T>`, pre-allocated buffers. Pin the voice thread's allocations. Use `GC.TryStartNoGCRegion` during encode/decode. Consider `[SkipLocalsInit]`. |
| 2 | **Opus encoding CPU on mobile** | HIGH | ARM NEON optimized libopus. Use 32kbps (not 64kbps). Reduce `complexity` to 3 on mobile. Profile on target devices early. |
| 3 | **Jitter buffer misconfiguration** | MEDIUM | Adaptive buffer. Start conservative (60ms), tighten based on measured jitter. Expose in settings for power users. |
| 4 | **NAT traversal failures** | MEDIUM | No TURN in MVP = some symmetric NATs won't work. Mitigate: use peer relay (mesh routing inherently supports this). Document requirement for at least UPnP or port-mapped connectivity for 1+ group member. |
| 5 | **Mesh routing convergence during churn** | MEDIUM | For 2-10 peers, convergence is sub-second. Risk is during multiple simultaneous joins/leaves. Mitigate: dampening timer (500ms) before recomputing routes after topology change. |
| 6 | **WebRTC DataChannel overhead for voice** | LOW-MEDIUM | SCTP framing adds ~28 bytes per message. Total per-frame: ~77 bytes overhead on a ~60-100 byte Opus frame. ~55% overhead ratio. Acceptable for MVP at small scale. Monitor actual bandwidth. |
| 7 | **Memory pressure from per-packet allocation** | MEDIUM | Use `ArrayPool<byte>.Shared` for all packet buffers. Use `MemoryPool<byte>` for WebRTC send buffers. |
| 8 | **Cross-platform audio API differences** | MEDIUM | Abstract behind `IAudioCaptureService` / `IAudioPlaybackService`. Windows: WASAPI (via NAudio). Android: AAudio. iOS/Mac: AVAudioEngine. Test on each platform early. |
| 9 | **boringtun native library distribution** | LOW | Must compile for each target: win-x64, android-arm64, ios-arm64, osx-arm64/x64. Use runtime-specific NuGet packaging. |
| 10 | **Clock drift between peers** | LOW | Affects timestamp-based ordering. Mitigate: use Lamport clocks for ordering, NTP-style offset estimation between peers via probe/pong timestamps. |

### 15.2 Performance Targets

| Metric | Target | Measurement |
|---|---|---|
| Voice end-to-end latency (direct) | < 100 ms | Capture → encode → send → receive → decode → playback |
| Voice end-to-end latency (1 relay hop) | < 200 ms | Add relay processing time |
| Capture-to-encode latency | < 5 ms | Profiler on voice thread |
| Route computation time (10 peers) | < 1 ms | Dijkstra on 45 edges |
| Group state sync time | < 500 ms | Full event log transfer for small groups |
| Memory usage (idle, no voice) | < 50 MB | Working set |
| Memory usage (voice active, 10 peers) | < 100 MB | Working set |
| CPU usage (voice active, encoding + mixing 9 streams) | < 15% of one core (desktop) | Per-thread profiling |

### 15.3 Performance Monitoring

Instrument key paths from day one:

```csharp
public sealed class VoicePipelineStats
{
    public double CaptureLatencyMs { get; set; }
    public double EncodeLatencyMs { get; set; }
    public double DecodeLatencyMs { get; set; }
    public double JitterBufferDepthMs { get; set; }
    public double MixingLatencyMs { get; set; }
    public int DroppedFrames { get; set; }
    public int RelayedFrames { get; set; }
    public double OutgoingBitrateKbps { get; set; }
    public double IncomingBitrateKbps { get; set; }
}
```

Expose in a debug overlay during development. Remove or hide behind a flag in release.

---

## 16. Dependency Map

### 16.1 NuGet Packages

| Package | Module | Purpose |
|---|---|---|
| `SIPSorcery` | Vox.Network | WebRTC DataChannels, ICE, STUN |
| `Microsoft.Data.Sqlite` | Vox.Chat, Vox.Core | Local storage for events, chat history, peer data |
| `System.IO.Pipelines` | Vox.Network | High-performance I/O for WireGuard tunnel |
| `System.Threading.Channels` | All | Producer-consumer threading |
| `Microsoft.Extensions.Logging` | All | Structured logging |
| `CommunityToolkit.Mvvm` | Vox.App | MVVM helpers (ObservableObject, RelayCommand) |

### 16.2 Native Libraries (P/Invoke)

| Library | Module | Source | Build |
|---|---|---|---|
| **libsodium** | Vox.Core | [libsodium](https://github.com/jedisct1/libsodium) | Pre-built binaries via `libsodium` NuGet or manual compile |
| **boringtun** | Vox.Network | [boringtun](https://github.com/cloudflare/boringtun) | Compile from Rust source as C dylib per platform |
| **libopus** | Vox.Voice | [opus-codec](https://opus-codec.org/) | Pre-built binaries via `Concentus.Native` NuGet or manual compile |
| **librnnoise** | Vox.Voice | [rnnoise](https://github.com/xiph/rnnoise) | Compile from C source per platform |

### 16.3 Alternative: Managed Fallbacks

For rapid prototyping or platforms where native libs are problematic:

| Native | Managed Alternative | Trade-off |
|---|---|---|
| libsodium | `NSec` or `System.Security.Cryptography` | NSec wraps libsodium but is managed-friendly. System.Security lacks Ed25519 in older runtimes. |
| boringtun | `Noise.NET` (Noise protocol only) | No full WireGuard — handshake-only authentication. |
| libopus | `Concentus` (pure C# Opus) | 3-5x slower encoding. Acceptable for MVP prototyping. |
| librnnoise | Skip noise suppression | Degrade gracefully — just disable the feature. |

---

## 17. Future Extensibility

The architecture is designed to accommodate these future features without structural changes:

### 17.1 Hosted Server Mode (TS3/Mumble Style)

A hosted server is architecturally identical to a peer that:
- Is always online.
- Has a static, publicly routable endpoint.
- Has elevated group permissions (e.g., admin).
- May run in headless mode (no UI).

**What changes:**
- `ITransportService` routes all traffic through the server peer instead of mesh.
- Server runs `MeshRouter` in centralized mode (star topology — server is always the relay).
- Group state is authoritative on the server (no need for CRDT conflict resolution).
- Server handles knock/admission without invite URLs (direct join by server address).

**What does NOT change:**
- All core types, packet structures, and service interfaces remain identical.
- The server is built from the same codebase (`Vox.Core` + `Vox.Network` + `Vox.Voice` + `Vox.Chat`).
- Clients don't need to know whether they're in P2P or server mode — the transport layer abstracts this.

### 17.2 Virtual LAN

WireGuard already creates encrypted point-to-point tunnels. A Virtual LAN feature would:
- Assign each peer a virtual IP (e.g., 10.0.0.0/24 subnet) within the WireGuard tunnel.
- Configure WireGuard to route all traffic in that subnet through the tunnel.
- Require the full WireGuard tunnel (not just Noise handshake), using boringtun or WireGuardNT.

**Architectural preparation:**
- `IWireGuardService` already abstracts tunnel management. Extend with `ConfigureTunnelRouting(subnet)`.
- The knock protocol already establishes WireGuard tunnels. VPN mode just keeps them longer and routes more traffic.

### 17.3 Bots

Bots are headless clients:
- Run as a console application using `Vox.Core` + `Vox.Network`.
- Join groups via invite URL, same as any peer.
- Receive events via `IGroupService.GroupEvents`.
- Send messages via `IChatService`.
- Optionally join voice channels (e.g., music bot) via `IVoicePipeline`.

**Architectural preparation:**
- All services are DI-injected and decoupled from UI.
- A `Vox.Bot.Host` project can compose the same services without MAUI/Blazor.

### 17.4 Multiple Channels

Currently, one text channel and one voice channel per group. To support multiple:
- Add `ChannelId` field to `ChatMessage` and `VoiceFrame` packets (already present in VoiceFrame).
- Add `ChannelCreated` / `ChannelDeleted` group events.
- UI adds channel list in sidebar.
- No protocol changes needed.

### 17.5 Video & Screen Share

Would require:
- WebRTC MediaStreams (not DataChannel) for efficient video encoding/decoding.
- VP8/VP9/AV1 codec support.
- SFU topology for video (full mesh doesn't scale — N² video streams is too expensive).
- Significant UI work (video grid, screen picker).

**Architectural preparation:**
- `ITransportService` already supports multiple channel types. Add `vox-video` DataChannel or switch to MediaStream for video.
- Mesh router gains awareness of media type (voice routes ≠ video routes).
- Voice pipeline pattern is reusable for video pipeline (capture → encode → route → decode → render).

---

## 18. Known Limitations & Trade-offs

### 18.1 Fundamental P2P Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| **No offline messages** | If all group members are offline, messages are lost until someone comes online | Messages queued locally and synced on reconnect. But messages sent to a group with no online members are lost. |
| **IP exposure** | Peers learn each other's IP addresses | WireGuard encrypts all traffic. Future: optional relay mode to hide IPs (like TURN). |
| **Stale invites** | If all bootstrap peers change IP, invite stops working | Include multiple bootstrap peers. Invites have expiry. Users regenerate invites as needed. |
| **NAT restrictions** | Symmetric NAT blocks direct connections | Mesh relay covers this (route through a peer with better connectivity). No TURN in MVP. |
| **Clock skew** | Affects event ordering | Lamport clocks provide logical ordering. Physical timestamps are advisory only. |

### 18.2 MVP Simplifications (to be addressed post-MVP)

| Simplification | Post-MVP Improvement |
|---|---|
| No key rotation when members leave | Implement group key rotation with forward secrecy |
| No message encryption (only transport encryption via WireGuard/DTLS) | Add end-to-end encryption for chat messages using group ratchet |
| No permission system | Role-based access control (admin, moderator, member) |
| No message editing/deletion | Add EditMessage / DeleteMessage events |
| No file sharing | Add file transfer via DataChannel with chunking |
| Full event log sync | Implement snapshots and incremental sync for large groups |
| Single STUN provider | Configurable STUN/TURN server list |

### 18.3 Security Model Summary

| Threat | Protection |
|---|---|
| Unauthorized join | Invite capsule + online member validation + WireGuard handshake |
| Eavesdropping | WireGuard tunnel (knock phase) + WebRTC DTLS (data phase) |
| Impersonation | Ed25519 signatures on all events and protocol messages |
| Replay attacks | Timestamp windows + packet IDs + Lamport clocks |
| Man-in-the-middle | Noise_IKpsk2 mutual authentication with pre-shared group key |
| Denial of service | Rate limiting on knock listener; TTL on relay frames |

---

## Appendix A: Connection Lifecycle State Machine

```
                    ┌──────────┐
                    │  IDLE    │
                    └────┬─────┘
                         │ User clicks "Join" with invite URL
                         ▼
                    ┌──────────┐
                    │ KNOCKING │──── timeout (5s) ───► FAILED
                    └────┬─────┘
                         │ Knock accepted
                         ▼
                    ┌──────────────┐
                    │ WG_HANDSHAKE │──── timeout (5s) ───► FAILED
                    └────┬─────────┘
                         │ Tunnel established
                         ▼
                    ┌──────────────┐
                    │  ADMITTING   │──── rejected ───► FAILED
                    └────┬─────────┘
                         │ Membership cert received
                         ▼
                    ┌──────────────┐
                    │  SYNCING     │  Receiving group state + peer list
                    └────┬─────────┘
                         │ Sync complete
                         ▼
                    ┌──────────────┐
                    │  CONNECTING  │  Establishing WebRTC with each peer
                    └────┬─────────┘
                         │ ≥1 peer connected
                         ▼
                    ┌──────────────┐
                    │  CONNECTED   │  Normal operation
                    └────┬─────────┘
                         │ User leaves / all peers disconnect
                         ▼
                    ┌──────────────┐
                    │ DISCONNECTED │
                    └──────────────┘
```

---

## Appendix B: Data Channel Message Flow

```
Voice (speaking):
  Mic → [Capture Thread] → Channel<short[]> → [Voice Thread] → Denoise → Encode
  → Channel<VoiceFrame> → [Transport] → MeshRouter.Distribute()
  → DataChannel("vox-voice") → to peer(s)      (unreliable, unordered)

Voice (listening):
  DataChannel("vox-voice") → Channel<IncomingVoice> → [Voice Receive]
  → JitterBuffer → Opus Decode → Channel<DecodedAudio>
  → [Playback Thread] → Mixer → Speaker

Chat:
  User types → ChatService.SendAsync() → Sign → Serialize
  → DataChannel("vox-chat") → to all peers     (reliable, ordered)

Presence:
  StatusChange → PresenceService → Sign → Serialize
  → DataChannel("vox-presence") → to all peers  (reliable, unordered)

Routing:
  ProbeService (1/sec) → ProbePacket
  → DataChannel("vox-routing") → to neighbors   (unreliable)
  PongPacket received → update LinkMetrics → recompute routes if changed
  LinkStateUpdate → DataChannel("vox-routing")   (reliable, unordered)

Signaling:
  New peer joins → SDP Offer/Answer exchange
  → DataChannel("vox-signaling") → relayed       (reliable, ordered)
```

---

## Appendix C: Build Order for MVP Implementation

Recommended implementation sequence, each phase building on the previous:

| Phase | Components | Validates |
|---|---|---|
| **1. Foundation** | `Vox.Core`: Identity, Crypto (libsodium), packet serialization, group types | Key generation, signing, capsule encrypt/decrypt |
| **2. Networking** | `Vox.Network`: Knock protocol, WireGuard handshake (boringtun), basic WebRTC DataChannel (SIPSorcery) | Two peers can connect, authenticate, open data channels |
| **3. Chat** | `Vox.Chat`: Message send/receive over DataChannel, SQLite storage, event model | Two peers exchange text messages |
| **4. Group Management** | `Vox.Core` + `Vox.Network`: Group create, invite, join flow, peer list sync, membership certs | Full join flow works end-to-end |
| **5. Voice (Minimal)** | `Vox.Voice`: Capture, Opus encode/decode (Concentus for quick start), playback, PTT | Two peers can voice chat (direct, no mesh) |
| **6. Mesh Routing** | `Vox.Network.Routing`: Probes, link-state, Dijkstra, relay frames | Three+ peers with relay routing |
| **7. Voice (Full)** | `Vox.Voice`: RNNoise, jitter buffer, adaptive buffer, mixing, device selection | Production-quality voice for ≤10 peers |
| **8. Presence** | `Vox.Network` + `Vox.Core`: Online/offline/away status, presence broadcast | Member list shows live status |
| **9. UI** | `Vox.App`: Blazor components, Tailwind styling, all screens | Usable application |
| **10. Hardening** | Error handling, reconnection, state recovery, logging, testing | Stable under adverse network conditions |

---

*End of architecture document.*
