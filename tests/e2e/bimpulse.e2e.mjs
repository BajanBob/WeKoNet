// Bim Pulse in a real browser at phone size: faceplate, rating a place,
// point-and-shoot pothole with GPS pin, reports list, QR/WhatsApp share.
//   node tests/e2e/bimpulse.e2e.mjs        (BIMPULSE_SHOTS=dir to save screenshots)
import { createRequire } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { startServer } from '../../apps/bimpulse/server.js';

const { chromium } = createRequire(import.meta.url)('playwright');
const SHOTS = process.env.BIMPULSE_SHOTS || null;
const PHOTO = Buffer.from('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAA0JCgsKCA0LCgsODg0PEyAVExISEyccHhcgLikxMC4pLSwzOko+MzZGNywtQFdBRkxOUlNSMj5aYVpQYEpRUk//2wBDAQ4ODhMREyYVFSZPNS01T09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0//wAARCACgAMgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDFooormPICiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooqe0s7m8k2W0LSEdcdB9T0HSgaTbsiCiultfCjZzeXIAz92IZyPqf8K0o/DumJGFaFpCP4mc5P5YFB1RwVWXkcRRXd/wBg6WEK/ZBgkH77Z/PPvTG8PaWyEC3KkjAYSNke/JoK+oVO6OHorqLrwouM2dyQcfdlGcn6j/CsK+067sHxcRELnAccqevf8OnWgwqUKlP4kVKKKKDEKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiur0DQ/J23l6n73rHGf4Pc+/8vr0DWjRlVlZEOkeGw6LPqIOCDiHkH2yf6fT6V0scccMYjiRUQdFUYA/CnUUj2qVGFJWigooooNQooooAKRlV0KOoZWGCCMgilooEc/qvhuOUNNYARyAEmL+Fj7en8unSuUZWRyjqVZTggjBBr0usbXdFW/Qz24C3Kj6CQeh9/Q/5DODE4RNc1NanGUUrKyOUdSrKcEEYINJQeWFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAa/hzT1vb8vKoaGEbmB6EnoP5n8Peu1qhodmLLS4kIIdx5j5BB3Htj24H4VfoPcw1L2dNd2FFFR3Fzb2qCS5nihQnAaRwoJ9OaRuSUVXs760vk32dzFMAATsbJXPTI6j8asUAFFFFAwoqO4ube1QSXM8UKE4DSOFBPpzUdnfWl8m+zuYpgACdjZK56ZHUfjTFcsUUUUhnJ+KtPWGZLyJQqSnbIB/e65/H+nvXP16LfWqXlnLbOcCRcZ9D2P54rztlZHKOpVlOCCMEGmePjKXJPmWzEooooOMKKKKACiiigAooooAKKKKACrWm2/2rUbeApvVnG4ZxlRyf0zVWtPw5/yHbb/AIF/6CaC6SUppPudzRRRSPoQrynxDeyX2t3UshbCuY0BBG1VOAMHkepHqTXq1cR4i8J3k2oy3mmokiTNuaPdtZWPU8nBGeevfpxWkGk9TKqm1ocpZXUtleRXUBxJEwYcnB9jjsehr2FHDorqGAYAjcpB/EHkV57o/hC/uLiKW/iWC2BVmV2+Z164wOR6HOCM16HRUaYUk0tQooorM1PKfEN7Jfa3dSyFsK5jQEEbVU4AweR6kepNU7K6lsryK6gOJImDDk4Pscdj0NdX4i8J3k2oy3mmokiTNuaPdtZWPU8nBGeevfpxVPR/CF/cXEUt/EsFsCrMrt8zr1xgcj0OcEZrdSVjlcZcx6Ejh0V1DAMARuUg/iDyKWiisDqCuG8RW/2fWJsJtWTEi85znqfzzXc1yHi7/kKRf9cB/wChNTOLHJOlcwqKKKDyAooooAKKKKACiiigAooooAK1PDTMuuQBWIDBgQD1G0n+grLq5pE/2bVbaXKgBwGLdADwT+RoNKTtUi/M9AooopH0AUUUUAFFFFABRRRQAUUUUAFFFFABXI+L2Y6lChY7RCCBngEk5/kPyrrq4nxLP5+sSAFSsShAV/M598kimceOdqVjJooooPHCiiigAooooAKKKKACiiigAooooA9B0m7F7p0M27c+3bJ0zuHXp09fxq3XIeFr/wAi8NrI2I5/u5PAf8+/T8q6+g93D1faU0+oVz0PiCQ+IpLOZFW3MhhX1DAkA/iePbj3z0NYPiTRHvttzZov2gcOvQyDtz0yP5fQUjrp8t7SN6iuLtdZ1LRnFreQl0QYCScEDkfK3cZ+vTiteDxXp8hRZUmhJHzEqCqnHtyfyouOVGS21N2isv8A4SLSP+fv/wAhv/hUE3inTY3Cp50wxnciYH05IoJVOfY2657XPEElhqMdvboriPDTA98/w+3GDn6e4Odd+J727BgtIBD5g2jaSz5J7Hj6dKt+HNClinF5fxBdozFG3JB67j6Y9D+mKDWNNQXNP7jp6KKKDnI7meO1tpJ5ThI1yff2HvXnUsjzSvLIcu7FmPqTXR+LL/7ljG3+3Lg/kOv44PtXM0zyMbV5p8q6BRRRQcQUUUUAFFFFABRRRQAUUUUAFFFFABXZ6FrS36CC4IW5UfQSD1Hv6j/I4ylVmRw6MVZTkEHBBoNqFaVKV0el0VhaR4hhnRYb5hHMAf3hwEbH8j+n8q3aR7VOpGorxYyaCG4QJPFHKoOQHUMM/jWVN4Z0uRAqRSQnOdySEn6c5rYooNVOUdmYP/CJaf8A89rr/vpf/ialg8L6ZFu3pLNnpvfGP++cVs0UFe1n3Iba0trRNttBHEMAHauCcdMnv+NTUUUEN3Cs7WdWj02HAw9w4+RP6n2/n/KLVddt7ENFERNcYOADlVPT5j/T27Vxs80lxM00zl5HOSxpnDicUoLlhuJLI80ryyHLuxZj6k0yiig8kKKKKACiiigAooooAKKKKACiiigAooooAKKKKACr1hq97YYWGTdH/wA835Xv+XXtVGigqMnF3izr7XxRaSnbcxPASeo+dQP5/pWlHqunyxh1vIAD/ecKfyPNefUUHXHHVFvqeifb7IoXF5b7QQCfMXAJ6d/Y/lTW1OwRCxvbfAGTiQE/kK89oosX9fl2OxuvE9lEMW6vO2MjA2r9Mnn9KwdQ1y9vtyb/ACYTxsTjI56nqeD9Pasyig56mKqVNGwooooOcKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD/9k=', 'base64');

const server = await startServer({ port: 0, host: '127.0.0.1', dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'bp-e2e-')) });
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 400, height: 860 }, deviceScaleFactor: 2, permissions: ['geolocation'], geolocation: { latitude: 13.0975, longitude: -59.6167 } });
const page = await ctx.newPage();
const problems = [];
page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
page.on('console', (m) => { if (m.type() === 'error' && !/leaflet|Failed to load resource/i.test(m.text())) problems.push(`console: ${m.text()}`); });
const shot = (n) => SHOTS && page.screenshot({ path: path.join(SHOTS, `${n}.png`), fullPage: n === 'plate' });

try {
  await page.goto(base + '/');
  await page.waitForSelector('.key');
  assert.equal(await page.locator('.key').count(), 12); // 11 sections + Share
  await shot('plate');

  // Rate a restaurant
  await page.click('.key:has-text("Best Dining")');
  await page.fill('#subject', 'Cuz Fish Shack');
  await page.fill('#text', 'x'.repeat(140));
  assert.equal((await page.inputValue('#text')).length, 100, 'typing stops at 100 characters');
  await page.fill('#text', 'Best cutter on the island, quick and friendly <img src=x onerror=alert(1)>');
  await page.click('#rating .star:has-text("5")');
  await page.click('#submit');
  await page.waitForSelector('#pane-see:not([hidden]) .leaders li .chip');
  assert.equal(await page.locator('.report img').count(), 0, 'submitted text must never become HTML');
  assert.match(await page.innerText('.report .txt'), /<img src=x/);
  await shot('dining-see');
  await page.click('#sheet-close');
  await page.waitForFunction(() => /5\.0/.test(document.querySelector('.key')?.parentElement?.innerText || ''));

  // Point and shoot a pothole
  await page.click('.key:has-text("Potholes Spotted")');
  await page.click('#submit');
  assert.match(await page.innerText('#form-msg'), /short note/);
  await page.fill('#text', 'Deep hole by the bus stop, Hwy 7 Hastings');
  await page.click('#rating .star:has-text("1")');
  await page.setInputFiles('#photo', { name: 'pothole.jpg', mimeType: 'image/jpeg', buffer: PHOTO });
  await page.waitForFunction(() => /Pinned from your phone/.test(document.querySelector('#loc-status')?.textContent || ''));
  await page.waitForSelector('#preview:not([hidden])');
  await shot('pothole-add');
  await page.click('#submit');
  await page.waitForSelector('#pane-see:not([hidden]) .report img');
  await page.waitForFunction(() => document.querySelector('.report img')?.naturalWidth > 0);
  assert.match(await page.getAttribute('.report a', 'href'), /maps\?q=13\.0975,-59\.6167/);
  await shot('pothole-see');
  await page.click('.linkbtn:has-text("Mark as fixed")');
  await page.waitForSelector('.linkbtn:has-text("1 said yes")');
  await page.click('#sheet-close');

  // Deep link opens a section; share sheet has QR + WhatsApp
  await page.goto(base + '/#traffic');
  await page.waitForSelector('#sheet[open] #sheet-title:has-text("Traffic Congestion")');
  await page.click('#sheet-close');
  await page.click('#share-btn');
  await page.waitForSelector('#share-sheet[open] canvas#qr');
  assert.ok((await page.$eval('#qr', (c) => c.width)) > 150);
  assert.match(await page.getAttribute('#wa', 'href'), /^https:\/\/wa\.me\/\?text=.*127\.0\.0\.1/);
  await shot('share');
  assert.deepEqual(problems, []);
  console.log('✓ Bim Pulse browser test passed');
} catch (e) {
  console.error('✗ Bim Pulse browser test failed:', e.message, problems);
  await shot('FAIL');
  process.exitCode = 1;
} finally {
  await browser.close(); server.close();
}
