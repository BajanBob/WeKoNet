# WeKoNet Connect

**WeKoNet — the Disposable Chat Software.**

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

All of this is covered by tests: `npm test` (crypto fuzzing, hostile-relay and load tests) and `npm run test:e2e` (real-browser attacks) (handshake, tampering, impostor, forged MAC, beacon forgery/expiry, ratchet replay, frame tamper, relay admission/cap/expiry, mailbox purge).

## One-tap calling (no app needed)
- **Call someone:** tap *Create beacon*, then send the invite on WhatsApp or let them scan the **QR code**.
- **The invite is one short link.** Tapping it rings, in the WeKoNet app or right in the browser, with no install or sign-up. The ringing screen shows the **caller's photo** and **Answer / Decline / Block**. The relay serves the web app at `/b/`.
- **The QR code answers at once.** It holds the same link with `.answer` added. Adding `.decline` or `.block` instead does those actions directly. The word is in the URL fragment, so it never reaches a server.
- **Decline** tells the caller "declined", sealed with the invite's own key. No camera, mic or identity is shared, and a declined 1-to-1 invite stops working at once.
- **Block** declines and blocks that caller's identity on this device. Their later calls are declined automatically. You can unblock them in *Settings → Blocked callers*.
- **Caller photo** (*Settings → Your photo*):
  - The picture is shrunk on the device to a ~5 KB JPEG.
  - It is **signed with the caller's identity key and bound to that one call**, then sealed with a key from the short link. The relay stores only ciphertext.
  - The ringing phone checks the signature against the identity pinned in the beacon, so nobody can swap the photo. During the call, photos are exchanged over the encrypted channel and kept with saved contacts.
  - A photo shows who the caller *claims* to be. The 6 security words and saved contacts are what prove it.
- **During a browser call,** a *Download the app* button opens in a new tab, so the call keeps running.
- **If a phone loses the relay** (network change, app in background), it reconnects and re-enters the room. A failed connection says why instead of hanging.
- **Calls between phones on mobile data need TURN.** Set `CF_TURN_KEY_ID` and `CF_TURN_API_TOKEN` on the relay. `scripts/relay-check.mjs` (the *Relay check* workflow) reports whether TURN is being handed out.

## Bim Pulse (apps/bimpulse)
A separate free public app in the same repo. People report **potholes** and **traffic** (a photo and a GPS pin) and rate the **best dining, soul food, chill spot, car and home insurance companies, supermarket, government department, health clinic and car company**.
- **The faceplate:** a tabular panel of 11 sections. Each key shows its average score (1 = worst, 5 = best), number of reports and current leader.
- **Reports:** 100 characters max, plus a score from 1 to 5. "Best" sections need the place's name. Different spellings of one place are grouped, and leaderboards use a weighted average so one review can't top a list.
- **Potholes:**
  - *Take photo* opens the phone camera and pins the GPS location. People can also tap the map.
  - The photo is shrunk on the phone and its EXIF data stripped before upload.
  - Pothole reports leave the map after 3 people mark them fixed, or after 90 days. Traffic reports show for 3 hours.
- **Sharing:** a QR code, WhatsApp, the phone's share menu and deep links (`/#potholes`). People can "Add to Home screen" to use it like an app.
- **Safety:**
  - Strict CSP, no inline code, and submitted text is shown only as plain text.
  - Same-site posting only, with per-address limits (30 reports and 12 photos an hour).
  - Remove an abusive report with `POST /api/hide` and the `x-admin-token` header. Render generates `ADMIN_TOKEN`.
- **Deploy:** the `bimpulse` service in `render.yaml` (Starter plan with a 1 GB disk at `/data`).

## Links, calls on every network, app lock
- **Short beacon links** (~47 characters, `https://wekonet.app/b/#s.…`): a sealed copy of the beacon is parked on your relay under an ID derived from the link's own key, so the relay holds only ciphertext. *Copy full link* (~340 characters, compact v2 format) still works if the relay restarts.
- **TURN through Cloudflare**: set `CF_TURN_KEY_ID` and `CF_TURN_API_TOKEN` on the relay (Render asks for them). The relay hands short-lived TURN credentials to people in a room, so calls connect on mobile data and *Hide my IP* works; no TURN password is built into the app.
- **App lock**: optional 4–8 digit PIN (Settings → App lock), stored as a salted PBKDF2 hash; locks after 0, 1 or 5 minutes in the background; 10 wrong PINs erase WeKoNet.
- **SOS records** can be kept 3 hours (default), 7 days or 30 days. Saved connections never expire on their own.

## Release signing
The Android build is always a release (non-debuggable) APK plus a Play Store bundle. Add these GitHub secrets so every build uses the same key: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`. `public/.well-known/assetlinks.json` holds that key's SHA-256 fingerprint so `https://wekonet.app/b/…` links open the app directly; if you use Google Play App Signing, add Play's app-signing fingerprint there too.

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

npm run cap:android           # then: cd android && ./gradlew assembleRelease
npm run cap:ios               # then open ios/App in Xcode, set Team, Archive
npm run dist:win              # Windows NSIS installer + portable .exe
npm run dist:pi               # Raspberry Pi arm64 .deb + AppImage
npm run relay                 # run the relay locally (ws://127.0.0.1:8787/ws)
```

Or push a tag (`git tag v1.0.0 && git push --tags`) and **GitHub Actions** builds and publishes everything (see below).

## Deploy the relay

### Render (current setup: `wss://wekonet-relay.onrender.com/ws`)
The app is built to use this relay by default. `render.yaml` holds the service settings:
- **Start command:** `node server/relay.js` · **Health check:** `/healthz`
- **Environment:** `HOST=0.0.0.0`, `MAX_CONN_PER_IP=2000`, `PENDING_ROOMS_PER_IP=2000`, `NEW_BOXES_PER_HOUR=20000` (Render's proxy hides client IPs, so these act as service-wide limits), optional `DOWNLOAD_URL` (your APK link, shown on the beacon page) and `ANDROID_CERT_SHA256` (lets beacon links open the app directly).
- Beacon links look like `https://wekonet-relay.onrender.com/b/#v1…` — the relay serves a small page there that opens the app (or offers the download). The key after `#` never reaches the server.
- Calls use public STUN by default. If calls fail between some networks (strict mobile carriers), add a TURN service in the `VITE_ICE_SERVERS` secret.

### Your own server
`deploy/docker-compose.yml` runs Caddy (automatic TLS, serves the web app and beacon landing page with security headers), the relay, and coturn. Edit the hostnames in `deploy/Caddyfile`, `deploy/turnserver.conf` and your `.env`, then `docker compose up -d`. Publish `public/.well-known/assetlinks.json` and `apple-app-site-association` with your signing fingerprints so beacon links open the app directly.

## GitHub output files
Released by `.github/workflows/build.yml` on every `v*` tag:

| File | Platform |
|---|---|
| `WeKoNet-1.0.0-android.apk` | Android — release build, signed (your key from `ANDROID_KEYSTORE_*` secrets, or a temporary key if none is set) |
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
