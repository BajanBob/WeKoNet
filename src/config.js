// Build-time configuration (set in .env or CI secrets; see .env.example).
// The relay and tile hosts are also baked into the Content-Security-Policy,
// so the app physically cannot talk to any other server.
const env = import.meta.env || {};

export const CONFIG = {
  relayUrl: env.VITE_RELAY_URL || 'wss://relay.wekonet.app/ws',
  appBase: env.VITE_APP_BASE || 'https://wekonet.app/b/',
  tileUrl: env.VITE_TILE_URL || 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
  iceServers: JSON.parse(env.VITE_ICE_SERVERS || JSON.stringify([
    { urls: ['stun:turn.wekonet.app:3478'] },
    { urls: ['turns:turn.wekonet.app:5349'], username: 'wekonet', credential: 'change-me' },
  ])),
};
