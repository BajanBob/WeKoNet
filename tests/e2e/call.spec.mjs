import { test, expect } from '@playwright/test';

// Each person is a separate browser profile (own storage, own identity).
async function person(browser, name) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(`${name} page error: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/favicon|tile\.openstreetmap/.test(m.text())) errors.push(`${name} console: ${m.text()}`);
  });
  await page.goto('/');
  await expect(page.locator('#my-id')).toHaveText(/^WKN-/);
  return { ctx, page, errors };
}

async function createBeacon(page, mode) {
  await page.locator('.seg label', { hasText: mode }).first().click();
  await page.getByRole('button', { name: 'Create beacon' }).click();
  const code = page.locator('dialog .beacon-link');
  await expect(code).toBeVisible();
  return (await code.textContent()).trim();
}

// The shared link is the one-tap Answer link: opening it joins the call directly.
async function joinFromLink(page, link) {
  await page.goto(link);
}

test('chat call: short link, matching security words, message delivered, end for all', async ({ browser }) => {
  const A = await person(browser, 'host');
  const B = await person(browser, 'guest');

  const link = await createBeacon(A.page, 'Chat');
  expect(link).toMatch(/\/b\/#s\.[A-Za-z0-9_-]{22}\.answer$/);
  expect(link.length).toBeLessThan(75);
  await A.page.getByRole('button', { name: 'Done' }).click();

  await joinFromLink(B.page, link);

  // Both sides finished the hybrid handshake and show the same six security words.
  const wa = A.page.locator('.sas-words'), wb = B.page.locator('.sas-words');
  await expect(wa).toBeVisible(); await expect(wb).toBeVisible();
  expect((await wa.textContent()).trim()).toBe((await wb.textContent()).trim());
  expect((await wa.textContent()).trim().split(/\s+/).length).toBe(6);

  // Encrypted chat over the data channel.
  await A.page.locator('nav [data-nav="chat"]').click();
  await A.page.getByPlaceholder('Encrypted message…').fill('hello from the host');
  await A.page.getByRole('button', { name: 'Send' }).click();
  await B.page.locator('nav [data-nav="chat"]').click();
  await expect(B.page.locator('.msg.in .bubble')).toContainText('hello from the host');

  await B.page.getByPlaceholder('Encrypted message…').fill('reply from the guest');
  await B.page.keyboard.press('Enter');
  await expect(A.page.locator('.msg.in .bubble')).toContainText('reply from the guest');

  // The in-call bar's End button is visible on the Chat screen and ends it for both.
  await A.page.getByRole('button', { name: 'End call' }).first().click();
  await expect(B.page.getByText('Call ended — beacon expired')).toBeVisible();

  expect([...A.errors, ...B.errors]).toEqual([]);
  await A.ctx.close(); await B.ctx.close();
});

test('video call: media flows both ways with fake camera and microphone', async ({ browser }) => {
  const A = await person(browser, 'host');
  const B = await person(browser, 'guest');
  const link = await createBeacon(A.page, 'Video');
  await A.page.getByRole('button', { name: 'Done' }).click();
  await joinFromLink(B.page, link);

  const remoteVideoPlaying = (page) => expect.poll(() => page.evaluate(() =>
    [...document.querySelectorAll('figure.tile:not(.me) video')].some((v) => v.srcObject && v.srcObject.getVideoTracks().length && v.readyState >= 2)
  ), { timeout: 45e3 }).toBe(true);
  await remoteVideoPlaying(A.page);
  await remoteVideoPlaying(B.page);

  await A.page.getByRole('button', { name: 'End call' }).first().click();
  await expect(B.page.getByText('Call ended — beacon expired')).toBeVisible();
  expect([...A.errors, ...B.errors]).toEqual([]);
  await A.ctx.close(); await B.ctx.close();
});

test('full (long) link pasted into the Join box still works', async ({ browser }) => {
  const A = await person(browser, 'host');
  const B = await person(browser, 'guest');
  await createBeacon(A.page, 'Voice');
  await A.page.getByRole('button', { name: 'Copy full link' }).click();
  const full = await A.page.evaluate(() => navigator.clipboard.readText());
  expect(full).toMatch(/#v2\./);
  await B.page.getByLabel('Beacon link').fill(full);
  await B.page.getByRole('button', { name: 'Join', exact: true }).click();
  // A plain link rings: Answer / Decline / Block.
  for (const name of ['Answer', 'Decline', 'Block']) await expect(B.page.getByRole('button', { name, exact: true })).toBeVisible();
  expect([...A.errors, ...B.errors]).toEqual([]);
  await A.ctx.close(); await B.ctx.close();
});

test('app lock: PIN required after reload, wrong PIN refused, right PIN unlocks', async ({ browser }) => {
  const A = await person(browser, 'user');
  await A.page.locator('nav [data-nav="settings"]').click();
  await A.page.getByRole('button', { name: 'Set a PIN' }).click();
  await A.page.getByLabel('New PIN', { exact: true }).fill('482915');
  await A.page.getByLabel('Repeat new PIN').fill('482915');
  await A.page.getByRole('button', { name: 'Save' }).click();
  await expect(A.page.getByRole('button', { name: 'Remove PIN' })).toBeVisible();

  await A.page.reload();
  const lock = A.page.locator('.lockscreen');
  await expect(lock).toBeVisible();
  await expect(A.page.locator('main')).toBeHidden();
  await A.page.getByLabel('PIN', { exact: true }).fill('111111');
  await A.page.getByRole('button', { name: 'Unlock' }).click();
  await expect(lock).toContainText('Wrong PIN. 9 tries left');
  await expect(A.page.getByRole('button', { name: 'Unlock' })).toBeEnabled({ timeout: 5e3 });
  await A.page.getByLabel('PIN', { exact: true }).fill('482915');
  await A.page.getByRole('button', { name: 'Unlock' }).click();
  await expect(lock).toHaveCount(0);
  await expect(A.page.locator('#my-id')).toBeVisible();
  expect(A.errors).toEqual([]);
  await A.ctx.close();
});
