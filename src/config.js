// Build-time configuration (set in .env or CI secrets; see .env.example).
// The relay and tile hosts are also baked into the Content-Security-Policy,
// so the app physically cannot talk to any other server.
const env = import.meta.env || {};

export const CONFIG = {
  relayUrl: env.VITE_RELAY_URL || 'wss://wekonet-relay.onrender.com/ws',
  appBase: env.VITE_APP_BASE || 'https://wekonet.app/b/',
  tileUrl: env.VITE_TILE_URL || 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
  iceServers: JSON.parse(env.VITE_ICE_SERVERS || JSON.stringify([
    // Public STUN servers help two devices find each other. For calls that
    // must work on every network (and for "Hide my IP"), add your own TURN
    // server through the VITE_ICE_SERVERS secret.
    { urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] },
  ])),
};
