import assert from 'node:assert/strict';
import { test } from 'node:test';
import bcur from '@ngraveio/bc-ur';
import { isUr, psbtToUr, UrReader } from '../web/ur.js';

const { UR, UREncoder, URDecoder } = bcur;

// Deterministic stand-ins for PSBTs of various sizes.
const fakePsbt = (length) => Uint8Array.from({ length }, (_, i) => (i * 131 + 7) % 256);
const cbor = (bytes) => {
  const head = bytes.length < 24 ? [0x40 | bytes.length] : bytes.length < 256 ? [0x58, bytes.length] : [0x59, bytes.length >> 8, bytes.length & 255];
  return Buffer.concat([Buffer.from(head), Buffer.from(bytes)]);
};

test('a single-part UR from the reference library is read', () => {
  const psbt = fakePsbt(80);
  const part = new UREncoder(new UR(cbor(psbt), 'crypto-psbt'), 500).nextPart();
  assert.ok(isUr(part));
  const reader = new UrReader();
  assert.equal(reader.receive(part), 1);
  assert.deepEqual(reader.result, psbt);
});

for (const [length, fragment] of [[300, 100], [1500, 120], [4000, 90]]) {
  test(`a ${length}-byte sequence from the reference library is read from its plain parts`, () => {
    const psbt = fakePsbt(length);
    const encoder = new UREncoder(new UR(cbor(psbt), 'crypto-psbt'), fragment);
    const reader = new UrReader();
    let progress = 0;
    for (let i = 0; i < encoder.fragmentsLength; i++) progress = reader.receive(encoder.nextPart().toUpperCase());
    assert.equal(progress, 1);
    assert.deepEqual(reader.result, psbt);
  });

  test(`a ${length}-byte sequence is read from fountain-coded parts alone`, () => {
    const psbt = fakePsbt(length);
    const encoder = new UREncoder(new UR(cbor(psbt), 'crypto-psbt'), fragment);
    // Skip every plain part: only the mixed ones that follow are scanned.
    for (let i = 0; i < encoder.fragmentsLength; i++) encoder.nextPart();
    const reader = new UrReader();
    let progress = 0;
    let scanned = 0;
    while (progress < 1) {
      progress = reader.receive(encoder.nextPart());
      assert.ok(++scanned < encoder.fragmentsLength * 6, 'the fountain code should converge');
    }
    assert.deepEqual(reader.result, psbt);
  });
}

test('parts in any order, with repeats and losses, still add up', () => {
  const psbt = fakePsbt(2500);
  const encoder = new UREncoder(new UR(cbor(psbt), 'crypto-psbt'), 100);
  const parts = Array.from({ length: encoder.fragmentsLength * 9 }, () => encoder.nextPart());
  // Drop two parts in three, then read what is left backwards, twice over.
  const kept = parts.filter((_, i) => i % 3 === 1).reverse();
  const reader = new UrReader();
  for (const part of [...kept, ...kept]) reader.receive(part);
  assert.deepEqual(reader.result, psbt);
});

for (const length of [60, 700, 3000]) {
  test(`a ${length}-byte PSBT written here is read by the reference library`, () => {
    const psbt = fakePsbt(length);
    const parts = psbtToUr(psbt, 150);
    assert.equal(parts.length, length + 3 <= 150 ? 1 : Math.ceil((length + 3) / 150));
    assert.ok(parts.every((part) => /^[A-Z0-9:/-]+$/.test(part)), 'parts use the QR alphanumeric set');
    const decoder = new URDecoder();
    for (const part of parts) decoder.receivePart(part);
    assert.ok(decoder.isSuccess(), decoder.resultError?.());
    const ur = decoder.resultUR();
    assert.equal(ur.type, 'crypto-psbt');
    assert.deepEqual(new Uint8Array(ur.decodeCBOR()), psbt);

    // And by the reader here.
    const reader = new UrReader();
    for (const part of parts) reader.receive(part);
    assert.deepEqual(reader.result, psbt);
  });
}

test('other content and damage are refused', () => {
  const reader = new UrReader();
  assert.throws(() => reader.receive('ur:crypto-seed/oeadgdlfwfdwlphlfsghcphfcsaybekkkbaejkaosezofptplpayftemckpfaxihfpgd'), /not a transaction/);
  const [part] = psbtToUr(fakePsbt(40));
  const damaged = part.slice(0, -2) + (part.endsWith('AA') ? 'BB' : 'AA');
  assert.throws(() => reader.receive(damaged), /Damaged/);
  assert.equal(isUr('cHNidP8BAHEC'), false);
});
