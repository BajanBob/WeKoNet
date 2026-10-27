// End-to-end tests: two separate browsers make real encrypted calls through a
// local relay. Run in CI (.github/workflows/e2e.yml) after a test build:
//   VITE_RELAY_URL=ws://127.0.0.1:8787/ws VITE_APP_BASE=http://127.0.0.1:4173/b/ VITE_E2E_LOCAL=1 npm run build
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  timeout: 120e3,
  expect: { timeout: 30e3 },
  retries: 1,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4173/',
    launchOptions: { args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] },
    permissions: ['camera', 'microphone', 'clipboard-read', 'clipboard-write'],
  },
  webServer: [
    {
      command: 'node server/relay.js',
      url: 'http://127.0.0.1:8787/healthz',
      cwd: '../..',
      env: { HOST: '127.0.0.1', PORT: '8787', ALLOWED_ORIGINS: 'http://127.0.0.1:4173' },
      reuseExistingServer: false,
    },
    {
      command: 'npx vite preview --host 127.0.0.1 --port 4173 --strictPort',
      url: 'http://127.0.0.1:4173/',
      cwd: '../..',
      reuseExistingServer: false,
    },
  ],
});
