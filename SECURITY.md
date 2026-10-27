# Security model

## Threats in scope
- **Malicious or compromised relay** — can drop, delay or replay messages, but cannot read anything, impersonate a beacon's inviter, or substitute keys without detection.
- **Network attacker / MITM** — defeated by TLS to the relay, AES-GCM-sealed signaling, signed handshake transcripts, key confirmation, beacon identity pinning and the 6-word SAS check.
- **Future quantum adversary recording traffic today** — ML-KEM-768 is mixed into every session key.
- **Script injection (XSS)** — strict CSP + Trusted Types + sanitizer; private keys are non-extractable CryptoKeys, so even injected code cannot export them.
- **Device seized later** — per-message ratchet wipes old keys; history is encrypted at rest and expires after 3 hours; guest installs self-wipe.

## Out of scope / residual risk
- A compromised device OS, malicious keyboard or screen-recorder (Android builds set `FLAG_SECURE`).
- Anyone who obtains a beacon link before it expires can join (that is what the link is for). Use short validity, 2-person calls, and check the security words.
- Metadata visible to the relay operator: connection times and IP addresses at the TLS layer (enable *Hide my IP* to keep your IP from peers; use a VPN/Tor to hide it from the relay).
- The saved-contact SOS mailbox key is long-lived (no per-message forward secrecy for offline SOS).

## Algorithms
| Purpose | Algorithm |
|---|---|
| Identity / signatures | ECDSA P-384 with SHA-384 |
| Key agreement | X25519 ‖ ECDH P-384 ‖ ML-KEM-768 (FIPS 203) |
| KDF | HKDF-SHA-384 with transcript-hash salt, labelled per purpose and direction |
| Encryption | AES-256-GCM, 96-bit IVs (random or salt‖counter), 128-bit tags |
| Key confirmation | HMAC-SHA-384 |
| Beacon | AES-256-GCM, 256-bit random key in URL fragment, signed payload |

"Military grade" is marketing language; the accurate claim is: AES-256-GCM and the CNSA-aligned P-384/SHA-384 suite, plus NIST post-quantum ML-KEM-768.

## Reporting
Please report vulnerabilities privately via GitHub Security Advisories on this repository.
