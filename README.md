# WeKoNet Connect

Beacon-initiated, end-to-end encrypted **voice, video, chat, live location and SOS** for up to **3 people** — with no phone number, no email and no account.

One codebase → **Android APK · iOS app · Windows .exe · Raspberry Pi (arm64 .deb / AppImage) · Linux · Web/PWA**.

## How it works

1. **Create a beacon.** Pick Voice / Video / Chat, 2 or 3 people, how long the connection stays open (*until the call ends · 1 hr · 2 hr · all day · keep live*) and how long the invite is valid.
2. **Send it on WhatsApp.** The beacon is a link like `https://wekonet.app/b/#v1.<256-bit key>.<AES-256-GCM ciphertext>`. Everything after `#` never leaves the phone, so no server (not even WhatsApp's link preview) learns the key.
3. **They tap it → the app opens straight into the encrypted call** (one tap to allow camera/mic; saved contacts can auto-join).
4. **When the call ends the beacon expires** — on the relay and on both devices — unless you chose a linger time. The guest is asked *Keep WeKoNet* or *Remove everything*.

People are identified by a **WeKoNet ID** (`WKN-XXXX-XXXX-XXXX-XXXX`) derived from a device-generated ECDSA P-384 key — never by phone or email.

## Security design

| Layer | What protects it |
|---|---|
| Invitation | Beacon sealed with AES-256-GCM (random 256-bit key in the URL fragment), signed by the inviter's P-384 identity, expiry-checked, single room |
| Key agreement | Hybrid **X25519 + ECDH P-384 + ML-KEM-768** (post-quantum). Secure if *any one* holds |
| Key derivation | **HKDF-SHA-384** over the full transcript hash → independent keys for chat, audio, video, files, signaling, confirmation — per direction |
| Chat / location / SOS | AES-256-GCM, per-message hash ratchet (forward secrecy), counters authenticated, replay rejected |
| Voice / video | DTLS-SRTP **plus** per-frame AES-256-GCM in a worker (RTCRtpScriptTransform / Insertable Streams) |
| Relay | Sees only random room tags and ciphertext; no logs; join requires a beacon-derived proof; max 3 per room |
| At rest | IndexedDB records encrypted with a **non-extractable** AES-256 key |
| Web hardening | Strict CSP (`script-src 'self'`, no `unsafe-inline`/`unsafe-eval`), **Trusted Types**, no inline handlers, DOMPurify with a 9-tag / 0-attribute allow-list, CI gate (`scripts/check-csp.mjs`) |

### Man-in-the-middle defences
1. Both sides **sign the whole handshake transcript** with their identity keys (stops key substitution / unknown-key-share).
2. **Key-confirmation MACs** (HMAC-SHA-384) both ways.
3. The guest already knows the inviter's identity **from the beacon** (delivered out-of-band over WhatsApp). In 2-person calls this pin is enforced; an impostor relay is rejected.
4. **Six security words** (SAS) shown on both screens — read them aloud; a mismatch ends the call.
5. SDP (which carries the DTLS fingerprints) travels inside the authenticated session, binding DTLS-SRTP to the verified identities.
6. Relay URL must be `wss://`; CSP pins the app to *your* relay host only.

All of this is covered by tests: `npm test` (handshake, tampering, impostor, forged MAC, beacon forgery/expiry, ratchet replay, frame tamper, relay admission/cap/expiry, mailbox purge).

## Running in the background
While a call or beacon room is open (every *Keep connection open* option: until the call ends, 1 hr, 2 hr, all day or keep live), WeKoNet stays connected when you leave the app, like WhatsApp:
- **Android** shows a "WeKoNet is connected" notification and keeps running until the call or beacon ends.
- **Windows / Linux / Raspberry Pi**: closing the window hides WeKoNet to the tray; use *Quit WeKoNet* in the tray menu to end it.
- **iOS** keeps an active call running in the background (audio/VoIP mode); an idle open beacon may be paused by iOS.

## Retention & self-purge
- History (messages, calls, SOS) and location trails are kept **at most 3 hours**, then deleted. Expired items disappear from the app at once and are deleted by a sweep every 5 minutes.
- **Every night at 01:00** the app purges expired beacons, lingering rooms, location trails older than 3 h and temporary data; a **guest install wipes everything**. If the app was closed at 01:00 the purge runs on next launch. The relay purges idle rooms and all stored mail at 01:00 too.

## SOS help mode
The red **SOS** button sends your live GPS position every 20 s — encrypted — to everyone in the current call **and** to every saved connection's mailbox. Their device sounds a siren, vibrates and opens the map at your location with an "Open in maps" link. Saved connections are created after a call with **Save connection**.

> WeKoNet is not an emergency service. Push delivery while the receiving app is fully closed needs FCM/APNs (see *Roadmap*).

## Build

```bash
cp .env.example .env          # point at your relay / TURN / tiles
npm install
npm test                      # crypto + MITM + relay tests
npm run dev                   # web dev server
npm run build                 # production web build (CSP injected)

npm run cap:android           # then: cd android && ./gradlew assembleDebug
npm run cap:ios               # then open ios/App in Xcode, set Team, Archive
npm run dist:win              # Windows NSIS installer + portable .exe
npm run dist:pi               # Raspberry Pi arm64 .deb + AppImage
npm run relay                 # run the relay locally (ws://127.0.0.1:8787/ws)
```

Or push a tag (`git tag v1.0.0 && git push --tags`) and **GitHub Actions** builds and publishes everything (see below).

## Deploy the relay
`deploy/docker-compose.yml` runs Caddy (automatic TLS, serves the web app and beacon landing page with security headers), the relay, and coturn. Edit the hostnames in `deploy/Caddyfile`, `deploy/turnserver.conf` and your `.env`, then `docker compose up -d`. Publish `public/.well-known/assetlinks.json` and `apple-app-site-association` with your signing fingerprints so beacon links open the app directly.

## GitHub output files
Released by `.github/workflows/build.yml` on every `v*` tag:

| File | Platform |
|---|---|
| `WeKoNet-android-debug.apk` | Android (sideload) |
| `WeKoNet-release.apk` | Android, signed (when `ANDROID_KEYSTORE_*` secrets are set) |
| `WeKoNet-ios-unsigned.ipa` | iOS — must be signed with your Apple Developer account |
| `WeKoNet-1.0.0-x64-nsis.exe` | Windows installer |
| `WeKoNet-1.0.0-x64-portable.exe` | Windows portable |
| `WeKoNet-1.0.0-arm64.deb` / `.AppImage` | Raspberry Pi 4/5 (64-bit OS) |
| `WeKoNet-1.0.0-x64.deb` / `.AppImage` | Linux desktop |
| `WeKoNet-web.zip` | Static web/PWA build |
| `ghcr.io/<owner>/wekonet-relay:latest` | Relay Docker image |

Secrets (optional): `VITE_ICE_SERVERS`, `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`, `WIN_CSC_LINK`, `WIN_CSC_KEY_PASSWORD`. Variables: `VITE_RELAY_URL`, `VITE_APP_BASE`, `VITE_TILE_URL`.

## Roadmap / known limits
- Background SOS delivery to a closed app (FCM/APNs wake-up push with an encrypted payload).
- Group calls are a 3-way mesh (each person uploads 2 streams) — fine for 3, not designed for more.
- Independent cryptographic audit before relying on it for life-safety use.
