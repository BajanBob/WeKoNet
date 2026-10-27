// Build-time configuration (set in .env or CI secrets; see .env.example).
// The relay and tile hosts are also baked into the Content-Security-Policy,
// so the app physically cannot talk to any other server.
const env = import.meta.env || {};

export const CONFIG = {
  relayUrl: env.VITE_RELAY_URL || 'wss://wekonet-relay.onrender.com/ws',
  appBase: env.VITE_APP_BASE || 'https://wekonet-relay.onrender.com/b/',
  tileUrl: env.VITE_TILE_URL || 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
  // Public STUN works for most home / mobile networks. For strict NATs add a
  // TURN server via VITE_ICE_SERVERS (media stays end-to-end encrypted through it).
  iceServers: JSON.parse(env.VITE_ICE_SERVERS || JSON.stringify([
    // STUN helps two devices find each other. TURN servers (for every network
    // and for "Hide my IP") are handed out by the relay per call — see
    // CF_TURN_KEY_ID / CF_TURN_API_TOKEN in render.yaml.
    { urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'] },
  ])),
};
