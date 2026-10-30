import { test } from 'node:test';
import assert from 'node:assert/strict';
import { qrMatrix, rsRemainder } from '../src/ui/qr.js';

test('qr: Reed-Solomon matches the ISO 18004 worked example', () => {
  const data = [0x20, 0x5b, 0x0b, 0x78, 0xd1, 0x72, 0xdc, 0x4d, 0x43, 0x40, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11];
  assert.deepEqual(rsRemainder(data, 10), [0xc4, 0x23, 0x27, 0x77, 0xeb, 0xd7, 0xe7, 0xe2, 0x5d, 0x17]);
});

// Reference matrix produced by OpenCV's QR encoder (version 5-M, byte mode) for the same link.
const REF = ["1fd0ce217f","104bd18841","17458fd55d","1750a23f5d","175a542a5d","1051a65441","1fd555557f","12ef9200","117324e1f9","122a9b6e96","1a6215bb04","12368c817e","df17bd1cf","1ab06c271b","5c5a576fc","f0872d2f6","7e59328ee","1e2b46afd2","771a22738","b37fbd626","1f0ddf0ec","23014a730","10ef38273c","1e08cf5436","18c8a47afc","17af5b21d8","5c595b7ec","5880ce144","1ce86fd3fb","15ed3d10","1fdee4f150","104212a51f","175dd335fd","174d466fe9","174c22a0c4","1044ff9716","1fdb98e227"];

test('qr: answer link encodes bit-for-bit like a reference encoder', () => {
  const m = qrMatrix('https://wekonet-relay.onrender.com/b/#s.Q2hlY2tUaGlzUVJDb2RlMQ.answer');
  assert.equal(m.length, 37);
  assert.deepEqual(m.map((r) => BigInt('0b' + r.map((v) => (v ? 1 : 0)).join('')).toString(16)), REF);
});

test('qr: long full beacon links still fit; absurd input is refused', () => {
  assert.ok(qrMatrix('x'.repeat(900)).length <= 25 * 4 + 17);
  assert.throws(() => qrMatrix('x'.repeat(2000)), /too long/);
});
