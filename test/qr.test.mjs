import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeQr, encodeQr } from '../web/qr.js';

// Paints the symbol as an RGBA image, `scale` pixels per module, with a
// quiet zone of four modules.
function rasterise({ width, modules }, scale) {
  const quiet = 4;
  const side = (width + 2 * quiet) * scale;
  const rgba = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let y = 0; y < width; y++) {
    for (let x = 0; x < width; x++) {
      if (!modules[y][x]) continue;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const at = (((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx) * 4;
          rgba[at] = rgba[at + 1] = rgba[at + 2] = 0;
        }
      }
    }
  }
  return { rgba, side };
}

// Base64 text like the wallet's payloads, deterministic.
function payload(length) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let text = 'FRST';
  for (let i = 0; text.length < length; i++) text += alphabet[(i * 37 + 11) % 64];
  return text;
}

for (const length of [56, 220, 420, 900]) {
  test(`a ${length}-character payload survives encoding and decoding`, () => {
    const text = payload(length);
    const { rgba, side } = rasterise(encodeQr(text), 4);
    assert.deepEqual(decodeQr(rgba, side, side), [text]);
  });
}

test('a part of an animated sequence survives too', () => {
  const text = `frostqr:2/7:Ab+/9z:${payload(380)}`;
  const { rgba, side } = rasterise(encodeQr(text), 3);
  assert.deepEqual(decodeQr(rgba, side, side), [text]);
});

test('an image without a code yields nothing', () => {
  assert.deepEqual(decodeQr(new Uint8ClampedArray(200 * 200 * 4).fill(255), 200, 200), []);
});
