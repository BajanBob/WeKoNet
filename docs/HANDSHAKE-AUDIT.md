# WeKoNet call handshake audit — 3 November 2026 (v1.2.0)

**Symptom reported:** the caller's phone stays on "waiting for them to tap Answer" after the other person answers the WhatsApp link in a browser (Brave). The person answering sees only their own camera.

## How a call connects
1. **Caller** creates a beacon. The room is opened on the relay (`create`) and the invite link is shared on WhatsApp.
2. **Person answering** opens the link and taps Answer. They `join` the room with the beacon's join proof, and the relay sends the caller `peer-joined`.
3. The person answering sends an encrypted `hello` to everyone already in the room. The two phones then complete the hybrid handshake (X25519 + P-384 + ML-KEM-768): `reply` → `finish`.
4. After the handshake the phones exchange WebRTC offer/answer/ICE (encrypted), and media goes direct, or through TURN when the networks block a direct link.

## Findings
| # | Finding | Effect | Fix (v1.2.0) |
|---|---|---|---|
| 1 | The app never checked that its relay connection was really alive. Android pauses apps in the background (e.g. while the caller is in WhatsApp sending the invite) and mobile networks drop idle connections without telling the phone. | The caller's socket looks open but is dead. The relay removes the caller after its 30–60 s heartbeat, so the other person answers into an **empty room**. The caller never notices and waits for ever. **This matches the reported symptom.** | The app pings the relay every 10 s, and at once when it returns to the screen or the network comes back. If no pong arrives within 8 s, it reconnects and rejoins. |
| 2 | On rejoin the relay still held the dead old connection for up to 60 s. | In a 2-person call the room looked full (`room-full`), so the caller couldn't get back in. | The rejoining app sends its old peer id (`was`). The relay drops the dead connection immediately and admits the new one. |
| 3 | The person answering ended their call when a caller they had never connected to dropped off the relay (added in 1.1.5). | A caller coming back from WhatsApp found the other person already gone. | The call ends only when a caller they were *connected* to leaves. |
| 4 | The person answering gave up after 15 s (1.1.6). | Too short when the caller is still in WhatsApp. | They now see "Waiting for the caller (ID)… connects as soon as they open WeKoNet again" and wait up to 3 minutes. |
| 5 | The caller got no signal between sending the invite and the end of the handshake. | Nothing to show that the invite was opened. | The caller now gets "They opened your invite ✓" from the relay's `peer-joined`, then "They answered ✓". |
| 6 | Each Android build is signed with a different temporary key, so updating needs an uninstall, which wipes the phone's identity. | The phone gets a new ID, and old invites in the chat ring a caller who no longer exists. | **Owner action:** add the `ANDROID_KEYSTORE_*` secrets. The ringing screen now shows the Caller ID and warns on invites older than 5 minutes. |
| 7 | No TURN server unless `CF_TURN_KEY_ID` / `CF_TURN_API_TOKEN` are set on Render. | The handshake succeeds, but audio/video can fail between two mobile networks (an error appears after about 30 s). | **Owner action:** add the Cloudflare TURN keys in Render. |
| 8 | Every push to the WeKoNet repository redeploys the relay, which forgets open rooms and short links. | A call created just before a deploy can't be answered. | Don't test during a deploy (2–5 min after a push); create a new beacon after it. |
| 9 | A beacon opened while the person answering was still in an older call was ignored (fixed in 1.1.5). | Answering looked successful but went nowhere. | A dead old call is left automatically; a live one asks first. |

**Unchanged and confirmed sound:** handshake cryptography and inviter pinning, transcript signatures, the AES-GCM sealing of signaling, and room admission by join proof. These are covered by the crypto and relay unit tests, and by the browser tests "malicious relay #1 and #2".

## New tests
- **Relay:** a dead connection is replaced via `was`, even when the room is full; a peer id from outside the room changes nothing; ping → pong.
- **Browser:** the caller's app is frozen (as Android does behind WhatsApp) while the call is answered, and the call connects once it resumes.
- **Browser:** the caller's relay connection goes silently dead (half-open, never closed); the heartbeat notices, the app rejoins with its old peer id, and the call connects.
- **Browser:** an old invite whose caller has gone shows "Waiting for the caller (ID)" instead of failing silently.

## Remaining owner actions
1. Add the 4 Android signing secrets to BajanBob/WeKoNet so the ID survives updates.
2. Add the Cloudflare TURN keys in Render (wekonet-relay → Environment).
3. Test on two phones: caller on 1.2.0. The person answering should **close old browser tabs** and open the newest invite.
