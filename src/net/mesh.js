// CallSession: one beacon room, up to 3 people, full mesh of pairwise
// hybrid-handshake sessions. Everything that leaves the device is encrypted:
//   relay hop     → AES-256-GCM (beacon-derived signaling key)
//   SDP / ICE     → + per-peer ratchet (handshake-derived, binds DTLS to identity)
//   chat/loc/SOS  → per-peer ratchet over the WebRTC data channel (DTLS inside)
//   voice/video   → per-frame AES-256-GCM (media worker) inside DTLS-SRTP
import { Signaling } from './signaling.js';
import { initiate, respond } from '../crypto/handshake.js';
import { Chain, encryptMsg, decryptMsg } from '../crypto/ratchet.js';
import { wekonetId, safetyNumber, samePub } from '../crypto/identity.js';

export const E2EE_MEDIA =
  typeof window !== 'undefined' && ('RTCRtpScriptTransform' in window ||
    (window.RTCRtpSender && 'createEncodedStreams' in RTCRtpSender.prototype));
const USE_SCRIPT_TRANSFORM = typeof window !== 'undefined' && 'RTCRtpScriptTransform' in window;

export class CallSession extends EventTarget {
  /**
   * @param {object} o
   * @param {object} o.identity   local identity {pub, privateKey, id}
   * @param {object} o.beacon     result of createBeacon() or openBeacon()
   * @param {'host'|'guest'} o.role
   * @param {RTCIceServer[]} o.iceServers
   * @param {boolean} o.hideIp    force TURN relay (hides your IP from peers)
   */
  constructor({ identity, beacon, role, iceServers, hideIp = false }) {
    super();
    this.identity = identity; this.beacon = beacon; this.role = role;
    this.payload = beacon.payload;
    this.inviterPub = role === 'guest' ? beacon.inviterPub : identity.pub;
    this.iceServers = iceServers; this.hideIp = hideIp;
    this.peers = new Map(); // peerId → state
    this.local = null; this.worker = null; this.deadline = null; this.ended = false;
  }

  emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }

  async start(mode = this.payload.mode) {
    if ((mode === 'voice' || mode === 'video') && !E2EE_MEDIA) {
      this.emit('warning', { message: 'This device cannot add WeKoNet frame encryption; calls are protected by DTLS-SRTP only.' });
    }
    await this.setMedia(mode);
    const sig = (this.sig = new Signaling(this.payload.sig, this.beacon.keys));
    sig.addEventListener('joined', (e) => this.#onJoined(e.detail));
    sig.addEventListener('peer-left', (e) => this.#dropPeer(e.detail.peer, 'left'));
    sig.addEventListener('ended', () => this.end(false));
    sig.addEventListener('relay-error', (e) => this.emit('error', { message: relayError(e.detail.code) }));
    sig.addEventListener('warning', (e) => this.emit('warning', e.detail));
    // Process signaling strictly in arrival order (handshake → SDP → ICE).
    this.queue = Promise.resolve();
    sig.addEventListener('signal', (e) => {
      this.queue = this.queue.then(() => this.#onSignal(e.detail)).catch((err) => this.#fail(e.detail.from, err));
    });
    await sig.connect();
    if (this.role === 'host') sig.create({ max: this.payload.max, linger: this.payload.linger, exp: this.payload.exp });
    else sig.join();
  }

  // ---------- media ----------
  async setMedia(mode) {
    this.mode = mode;
    if (mode !== 'voice' && mode !== 'video') return;
    this.local = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: mode === 'video' ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' } : false,
    });
    this.emit('local-stream', { stream: this.local });
  }

  #worker() {
    if (!this.worker) this.worker = new Worker(new URL('./media-worker.js', import.meta.url), { type: 'module' });
    return this.worker;
  }

  #protect(endpoint, op, key, kind) {
    if (!E2EE_MEDIA) return;
    const opts = { op, key: key.slice().buffer, kind };
    if (USE_SCRIPT_TRANSFORM) {
      endpoint.transform = new RTCRtpScriptTransform(this.#worker(), opts);
    } else {
      const { readable, writable } = endpoint.createEncodedStreams();
      this.#worker().postMessage({ ...opts, readable, writable }, [readable, writable]);
    }
  }

  toggleMic(on) { this.local?.getAudioTracks().forEach((t) => { t.enabled = on; }); }
  toggleCam(on) { this.local?.getVideoTracks().forEach((t) => { t.enabled = on; }); }

  async switchCamera() {
    const cur = this.local?.getVideoTracks()[0];
    if (!cur) return;
    const facing = cur.getSettings().facingMode === 'environment' ? 'user' : 'environment';
    const s = await navigator.mediaDevices.getUserMedia({ video: { facingMode: facing } });
    const nt = s.getVideoTracks()[0];
    for (const p of this.peers.values()) {
      const snd = p.pc?.getSenders().find((x) => x.track?.kind === 'video');
      await snd?.replaceTrack(nt);
    }
    this.local.removeTrack(cur); cur.stop(); this.local.addTrack(nt);
    this.emit('local-stream', { stream: this.local });
  }

  // ---------- room / handshake ----------
  async #onJoined({ peer, peers, deadline, ice }) {
    this.me = peer; this.deadline = deadline;
    // TURN servers + short-lived credentials handed out by the relay (Cloudflare).
    if (Array.isArray(ice) && ice.length) this.iceServers = [...ice];
    if (this.hideIp && !this.iceServers.some((s) => [].concat(s.urls).some((u) => /^turns?:/.test(u)))) {
      this.emit('warning', { message: '“Hide my IP” needs a TURN server, which this relay does not provide yet — your IP address may be visible to the other person.' });
    }
    this.emit('room', { me: peer, deadline, linger: this.payload.linger });
    if (deadline) this.deadlineTimer = setTimeout(() => this.end(false), Math.max(0, deadline - Date.now()));
    // Newcomer initiates a handshake with everyone already in the room.
    for (const other of peers) {
      // In a 2-person call the only other person MUST be the inviter (strict pin).
      const expect = this.role === 'guest' && this.payload.max === 2 ? this.inviterPub : null;
      const hs = await initiate({ identity: this.identity, room: this.payload.room, expectPeer: expect });
      this.peers.set(other, { hs, role: 'I' });
      await this.sig.send(other, hs.hello);
    }
  }

  async #onSignal({ from, msg }) {
    let p = this.peers.get(from);
    if (msg.t === 'hello') {
      if (p) throw new Error('duplicate hello');
      if (this.peers.size >= this.payload.max - 1) throw new Error('room full');
      const expect = this.role === 'guest' && this.payload.max === 2 ? this.inviterPub : null;
      const r = await respond({ identity: this.identity, room: this.payload.room, hello: msg, expectPeer: expect });
      this.peers.set(from, { hs: r, role: 'R' });
      await this.sig.send(from, r.reply);
      return;
    }
    if (!p) throw new Error('unknown peer');
    if (msg.t === 'reply' && p.role === 'I' && !p.session) {
      const { finish, session } = await p.hs.onReply(msg);
      await this.sig.send(from, finish);
      return this.#established(from, p, session);
    }
    if (msg.t === 'finish' && p.role === 'R' && !p.session) {
      return this.#established(from, p, await p.hs.onFinish(msg));
    }
    if (msg.t === 'rtc' && p.session) {
      return this.#onRtc(from, p, await decryptMsg(p.sigRx, msg.e));
    }
    throw new Error('unexpected message');
  }

  async #established(peerId, p, session) {
    p.session = session; delete p.hs;
    p.tx = new Chain(session.send.chat, 'chat'); p.rx = new Chain(session.recv.chat, 'chat');
    p.sigTx = new Chain(session.send.signal, 'sig'); p.sigRx = new Chain(session.recv.signal, 'sig');
    p.id = await wekonetId(session.peerPub);
    p.isInviter = samePub(session.peerPub, this.inviterPub);
    p.safety = await safetyNumber(this.identity.pub, session.peerPub);
    this.emit('peer', { peer: peerId, id: p.id, sas: session.sas, safety: p.safety, isInviter: p.isInviter });
    this.#makePc(peerId, p);
    if (p.role === 'I') {
      const offer = await p.pc.createOffer();
      await p.pc.setLocalDescription(offer);
      await this.#sendRtc(peerId, p, { sdp: p.pc.localDescription.toJSON() });
    }
  }

  async #sendRtc(peerId, p, body) {
    await this.sig.send(peerId, { t: 'rtc', e: await encryptMsg(p.sigTx, 'rtc', body) });
  }

  #makePc(peerId, p) {
    const cfg = { iceServers: this.iceServers, bundlePolicy: 'max-bundle', rtcpMuxPolicy: 'require' };
    if (this.hideIp) cfg.iceTransportPolicy = 'relay';
    if (E2EE_MEDIA && !USE_SCRIPT_TRANSFORM) cfg.encodedInsertableStreams = true;
    const pc = (p.pc = new RTCPeerConnection(cfg));

    pc.onicecandidate = (e) => { if (e.candidate) this.#sendRtc(peerId, p, { ice: e.candidate.toJSON() }); };
    pc.onconnectionstatechange = () => {
      this.emit('peer-state', { peer: peerId, state: pc.connectionState });
      if (pc.connectionState === 'failed') this.#dropPeer(peerId, 'connection failed');
    };

    // Data channel (pre-negotiated, same id on both sides → no in-band DCEP race)
    p.dc = pc.createDataChannel('wekonet', { negotiated: true, id: 0, ordered: true });
    p.dc.onopen = () => this.emit('channel-open', { peer: peerId });
    p.dc.onmessage = async (e) => {
      try {
        if (typeof e.data !== 'string' || e.data.length > 65536) return;
        const env = JSON.parse(e.data);
        const body = await decryptMsg(p.rx, env);
        if (env.k === 'bye') return this.#dropPeer(peerId, 'hung up');
        this.emit('message', { peer: peerId, from: p.id, kind: env.k, body });
      } catch (err) { this.emit('warning', { message: `Rejected a message: ${err.message}` }); }
    };

    p.protected = new WeakSet();
    if (p.role === 'I') {
      // Offerer defines the m-lines: one audio + one video, always encrypted.
      for (const kind of ['audio', 'video']) {
        const track = this.local?.getTracks().find((t) => t.kind === kind);
        const tr = pc.addTransceiver(track || kind, { direction: 'sendrecv', streams: this.local ? [this.local] : [] });
        preferCodec(tr, kind);
        this.#protectOnce(p, tr.sender, 'encrypt', p.session.send[kind], kind);
      }
    }
    pc.ontrack = (e) => {
      const kind = e.track.kind;
      this.#protectOnce(p, e.receiver, 'decrypt', p.session.recv[kind], kind);
      this.emit('remote-track', { peer: peerId, stream: e.streams[0] || new MediaStream([e.track]) });
    };
  }

  #protectOnce(p, endpoint, op, key, kind) {
    if (p.protected.has(endpoint)) return;
    p.protected.add(endpoint);
    this.#protect(endpoint, op, key, kind);
  }

  /** Answerer: attach local tracks to the transceivers the offer created. */
  async #attachAnswerTracks(p) {
    for (const tr of p.pc.getTransceivers()) {
      const kind = tr.receiver.track.kind;
      const track = this.local?.getTracks().find((t) => t.kind === kind) || null;
      this.#protectOnce(p, tr.sender, 'encrypt', p.session.send[kind], kind);
      if (track) { await tr.sender.replaceTrack(track); tr.sender.setStreams?.(this.local); }
      tr.direction = 'sendrecv';
      preferCodec(tr, kind);
    }
  }

  async #onRtc(peerId, p, body) {
    const pc = p.pc;
    if (body.sdp) {
      await pc.setRemoteDescription(body.sdp);
      for (const c of (p.iceQueue || []).splice(0)) await pc.addIceCandidate(c).catch(() => {});
      if (body.sdp.type === 'offer') {
        await this.#attachAnswerTracks(p);
        await pc.setLocalDescription(await pc.createAnswer());
        await this.#sendRtc(peerId, p, { sdp: pc.localDescription.toJSON() });
      }
    } else if (body.ice) {
      if (!pc.remoteDescription) (p.iceQueue ||= []).push(body.ice);
      else await pc.addIceCandidate(body.ice).catch(() => {});
    }
  }

  // ---------- messaging ----------
  async sendTo(peerId, kind, body) {
    const p = this.peers.get(peerId);
    if (!p?.dc || p.dc.readyState !== 'open') return false;
    p.dc.send(JSON.stringify(await encryptMsg(p.tx, kind, body)));
    return true;
  }

  async broadcast(kind, body) {
    const out = [];
    for (const id of this.peers.keys()) out.push(this.sendTo(id, kind, body));
    return Promise.all(out);
  }

  // ---------- teardown ----------
  #fail(peerId, err) {
    this.emit('security', { peer: peerId, message: err.message });
    this.#dropPeer(peerId, err.message);
  }

  #dropPeer(peerId, reason) {
    const p = this.peers.get(peerId);
    if (!p) return;
    try { p.pc?.close(); } catch { /* ignore */ }
    p.tx?.destroy(); p.rx?.destroy(); p.sigTx?.destroy(); p.sigRx?.destroy();
    this.peers.delete(peerId);
    this.emit('peer-left', { peer: peerId, reason });
  }

  /** End the call. `forAll` kills the beacon on the relay for everyone. */
  async end(forAll = false) {
    if (this.ended) return;
    this.ended = true;
    clearTimeout(this.deadlineTimer);
    await this.broadcast('bye', {}).catch(() => {});
    for (const id of [...this.peers.keys()]) this.#dropPeer(id, 'call ended');
    this.local?.getTracks().forEach((t) => t.stop());
    this.worker?.terminate();
    if (forAll || this.payload.linger === 'end') this.sig?.endForAll(); else this.sig?.leave();
    setTimeout(() => this.sig?.close(), 200);
    this.beacon.beaconKey?.fill(0); // token beacon expires locally too
    this.emit('ended', {});
  }
}

function preferCodec(tr, kind) {
  try {
    const caps = RTCRtpReceiver.getCapabilities?.(kind);
    if (!caps || !tr.setCodecPreferences) return;
    const want = kind === 'audio' ? 'audio/opus' : 'video/vp8';
    const sorted = [...caps.codecs].sort((a, b) => (b.mimeType.toLowerCase() === want) - (a.mimeType.toLowerCase() === want));
    tr.setCodecPreferences(sorted);
  } catch { /* browser default */ }
}

function relayError(code) {
  return ({
    'room-full': 'This WeKoNet call already has 3 people.',
    'no-such-beacon': 'This beacon has ended or is invalid.',
    'beacon-expired': 'This beacon has expired.',
    'room-exists': 'Beacon already in use.',
  })[code] || `Relay error (${code}).`;
}
