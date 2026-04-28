# Vox Architecture (MVP)

Version: 0.1  
Status: MVP Design  
Scope: 2–10 peers, Pure P2P

---

## 1. Core Vision

Vox is a privacy-first, decentralized communication platform combining:

- Peer-to-peer text + voice
- WireGuard-based cryptographic handshake
- WebRTC data/media transport
- Torrent-style mesh routing for voice
- Discord-like UX
- No permanent central servers

Groups only exist while at least one member is online.

Optional future modes:
- Bot-assisted relay
- Fully hosted servers (TS3/Mumble style)
- Virtual LAN

MVP ships Pure P2P only.

---

## 1.1 Design Principles

- No central identity registry
- Invite URLs are discovery only, never authorization
- Group admission happens exclusively via WireGuard handshake with an online peer
- Voice defaults to mesh routing, not client-server
- UI never talks directly to crypto or transport layers
- Plugin-ready seams exist, but no plugin loader in MVP
- Architecture must support future hosted servers and LAN without refactor

---

## 2. Architecture Layers

```
+---------------------------+
| Blazor Hybrid UI (MAUI)   |
+---------------------------+
| Application Facade        |
+---------------------------+
| Chat / Voice / Presence   |
+---------------------------+
| Mesh Routing              |
+---------------------------+
| WebRTC Transport          |
+---------------------------+
| WireGuard Handshake       |
+---------------------------+
| Crypto + Identity         |
+---------------------------+
| Platform I/O              |
+---------------------------+
```

Each layer only depends downward.

UI never accesses Transport/Crypto directly.

---

## 2.1 UI Shell (Discord-like)

Phase 5 introduces a Discord-style layout:

Layout regions:

- Left Rail: Groups
- Left Sidebar: Channels
- Center: Active View (Chat or Voice)
- Right Sidebar (optional): Member list / Presence

Rules:

- Group selection drives channel list
- Channel selection drives active view
- Presence only shown for admitted peers
- UI must survive transient disconnects
- All UI actions go through Application Facade services

---

## 2.2 Theming & Customization Strategy

UI uses Tailwind CSS mapped to CSS variables (design tokens):

Examples:

- `--vox-bg`
- `--vox-panel`
- `--vox-text`
- `--vox-muted`
- `--vox-accent`
- `--vox-danger`
- `--vox-border`
- `--vox-radius`

Tailwind semantic classes map to tokens.

MVP ships dark theme only.

Future: user themes + group themes.

---

## 3. Identity

Each client generates:

- Ed25519 keypair (identity)
- Display name (non-unique, user-chosen)

Identity is:

- Stored encrypted locally
- Used for signing messages
- Used for group membership
- Used for presence

No central lookup. No global user search. No "DM by Name#1234".

Presence visible only to admitted peers and accepted contacts.

---

## 3.1 Contact Model (No Global Search)

Display names are non-unique and never used for routing or discovery.

Contacts are established only via:

1. **Shared group membership** — peers admitted to the same group can see each other
2. **Contact Link / QR** — out-of-band exchange (URL or QR code)

Contact Link contains:

- PeerId (Ed25519 public key)
- Current endpoints (hints, not authorization)
- Signature proving ownership

Contact flow:

1. User A copies Contact Link (or shows QR)
2. User B opens link → sends ContactRequest via Knock
3. User A receives prompt → Accept / Reject
4. On accept: mutual contact stored locally, presence shared when online

Rules:

- Contact Link / QR or shared group membership required for any interaction
- Contacts are stored locally after handshake acceptance
- No central contact directory
- QR code support deferred to mobile platform phase (hooks present in code)

---

## 3.2 Unified Capsule Links

All shareable links (group invites, contact links) use a single `CapsuleCodec`
that enforces a consistent encoding pipeline:

```
Serialize → Prefix(version + type) → GZIP → Encrypt(AEAD) → Base64URL(no padding)
```

Key properties:

- **Version byte** (0x01): first byte, allows future format evolution
- **CapsuleType byte**: 0x01 = GroupInvite, 0x02 = ContactInvite
- **Compression before encryption**: GZIP applied to the version+type+payload envelope before AEAD
- **AEAD**: XChaCha20-Poly1305 (same algorithm used everywhere)
  - GroupInvite: encrypted with group symmetric key (opaque to joiner)
  - ContactInvite: encrypted with well-known key (public info, signature provides integrity)
- **Base64URL**: URL-safe alphabet (`-`, `_`), no `=` padding, no line breaks
- **Fully self-contained**: no server-side mapping, short codes, or central lookup

URL formats:

- Group invite: `vox://join/<token>?ep=<endpoints>&bpk=<wg_key>`
- Contact link: `vox://contact/<token>`

Decoding reverses the pipeline: Base64URL → Decrypt → Decompress → Parse version + type → Deserialize.

QR codes encode the same Base64URL token directly.

There is no global search. Contacting a user requires either a shared group
or exchanging a contact link/QR out-of-band.

---

## 4. Groups

Groups support:

- Name
- Invite URL / QR
- Optional password
- Roles: Owner / Admin / Member
- Text channels
- Voice channels

Groups exist as distributed signed state across peers.

Join rule:

A user may only join if at least one group member is online.

Group state uses:

- Event sourcing
- Signed events
- Lamport clocks
- Anti-entropy sync

---

## 5. Transport Overview

### Handshake

WireGuard is mandatory for:

- Identity verification
- Group admission
- Secure tunnel establishment

Invite URLs only provide discovery hints.

Actual authorization occurs during WireGuard handshake.

### Media + Data

After WireGuard:

- WebRTC handles:
  - DataChannels (chat, routing, presence)
  - Unreliable DataChannel for voice

STUN only in MVP.

No TURN.

---

## 6. Connection Lifecycle

1. User opens invite URL
2. Client sends encrypted UDP Knock
3. Online peer validates capsule + password
4. WireGuard tunnel established
5. Membership certificate issued
6. Peer list + group snapshot delivered
7. WebRTC connections formed
8. Mesh routing stabilizes
9. Presence becomes visible

---

## 7. Mesh Voice Routing

Voice is distributed via torrent-style mesh:

- Every node publishes audio
- Nodes relay audio for others
- Best paths selected dynamically

Metrics:

- RTT
- Jitter
- Packet loss
- Stability
- Hardware capacity

Routing:

- Direct preferred
- Relay used if better
- Dijkstra over partial mesh
- Multicast trees per speaker
- TTL + packet IDs prevent loops
- Backup paths maintained
- Failover <3s target

Groups ≤5 may use full mesh.

Routing reliability model:

- LinkStateUpdate: reliable delivery
- RoutingProbe / RoutingPong: unreliable delivery
- Voice frames: unreliable delivery
- Chat and signaling: reliable delivery

This prevents routing measurement traffic from interfering with media latency.

---

## 8. Voice Pipeline

Pipeline:

Capture
→ Push-to-talk / VAD
→ Noise suppression
→ Opus encode (48kHz / 20ms)
→ Mesh distribute
→ Jitter buffer
→ PCM mix
→ Playback

Controls:

- Mic selection
- Gain
- Mute/deafen
- Per-user volume

---

## 9. Chat

Chat uses reliable WebRTC DataChannel.

Features:

- Signed messages
- Deduplication
- Retry while peers online
- Minimal local history

No offline delivery in MVP.

---

## 10. Presence

Presence states:

- Online
- Idle
- DND
- Offline

Presence is exchanged only after admission.

No public presence directory.

---

## 11. Application Facade

UI communicates exclusively through:

- IGroupService
- IChatService
- IVoiceService
- IPresenceService
- IIdentityService
- IContactService

These hide transport/crypto complexity.

---

## 12. Module Breakdown

### Vox.Core

- Identity
- Crypto
- Groups
- Events
- Interfaces

### Vox.Network

- WireGuard
- UDP Knock
- WebRTC
- Packet serialization

### Vox.Mesh

- Routing
- Probes
- Link-state

### Vox.Chat

- Messaging
- History
- Sync

### Vox.Voice

- Audio capture/playback
- Opus
- Mixer
- Jitter buffer

### Vox.App

- MAUI host
- Blazor UI
- Tailwind
- DI

---

## 13. UI Extensibility (Future)

MVP defines extension seams only.

No plugin loader.

Interfaces:

- IUiRouteProvider
- IUiPanelProvider
- ICommandProvider
- ISettingsSectionProvider
- IMessageRenderer

Rules:

- Plugins can only access Application Facade
- No access to WireGuard/WebRTC/Crypto
- User consent required (future)

DI must support IEnumerable<T>.

---

## 14. Bots (Future)

Bots are headless clients:

- No UI
- Same protocol as normal peers
- Optional message relay or rendezvous

Not part of MVP.

---

## 15. Hosted Servers (Future)

Dedicated server mode:

- Always-on peer
- Star topology
- Central voice/chat

Transport layer abstraction keeps this possible.

---

## 16. Virtual LAN (Future)

Optional encrypted subnet:

- Explicit consent
- Group password
- For game hosting

Architectural hooks exist but implementation deferred.

---

## 17. Threading Model

- Dedicated threads for audio I/O
- Channel<T> queues between pipeline stages
- Routing table guarded by ReaderWriterLockSlim
- Zero-allocation hot paths using pools/ring buffers

---

## 18. Performance Targets

- Direct voice latency <100ms
- Relayed voice <200ms
- Mesh convergence <3s
- No GC in audio hot path

---

## 19. Known MVP Limitations

- No offline messages
- No global user search or Name#1234 DM lookup
- IP exposure to peers
- Symmetric NAT failures possible
- No TURN
- No plugins
- No video/screen share
- No LAN
- No QR code scanning (mobile phase)

---

## 20. Phase Roadmap

Phase 0: Repo + tooling
Phase 1: Identity + Crypto
Phase 2: WireGuard handshake
Phase 3: Groups + invites
Phase 4: WebRTC connections
Phase 5: UI + Chat + Presence + Contacts
Phase 6: Voice direct
Phase 7: Mesh routing
Phase 8: Polish

---