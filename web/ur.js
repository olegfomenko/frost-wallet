// Uniform Resources (UR), the QR format other wallets use for PSBTs:
// `ur:crypto-psbt/...`, as one code or as an animated sequence (BCR-2020-005,
// with fountain-coded parts as in BCR-2024-001).

import { sha256 } from '@noble/hashes/sha2.js';

const WORDS = 'able acid also apex aqua arch atom aunt away axis back bald barn belt beta bias blue body brag brew bulb buzz calm cash cats chef city claw code cola cook cost crux curl cusp cyan dark data days deli dice diet door down draw drop drum dull duty each easy echo edge epic even exam exit eyes fact fair fern figs film fish fizz flap flew flux foxy free frog fuel fund gala game gear gems gift girl glow good gray grim guru gush gyro half hang hard hawk heat help high hill holy hope horn huts iced idea idle inch inky into iris iron item jade jazz join jolt jowl judo jugs jump junk jury keep keno kept keys kick kiln king kite kiwi knob lamb lava lazy leaf legs liar limp lion list logo loud love luau luck lung main many math maze memo menu meow mild mint miss monk nail navy need news next noon note numb obey oboe omit onyx open oval owls paid part peck play plus poem pool pose puff puma purr quad quiz race ramp real redo rich road rock roof ruby ruin runs rust safe saga scar sets silk skew slot soap solo song stub surf swan taco task taxi tent tied time tiny toil tomb toys trip tuna twin ugly undo unit urge user vast very veto vial vibe view visa void vows wall wand warm wasp wave waxy webs what when whiz wolf work yank yawn yell yoga yurt zaps zero zest zinc zone zoom'.split(' ');
// The "minimal" style: first and last letter of each word, one word per byte.
const MINIMAL = WORDS.map((word) => word[0] + word[3]);
const BYTE_OF = new Map(MINIMAL.map((pair, byte) => [pair, byte]));

const TYPES = ['crypto-psbt', 'psbt'];

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

const uint32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

// Bytes as minimal bytewords, with their CRC-32 appended.
function bytewords(bytes) {
  let text = '';
  for (const byte of concat(bytes, uint32(crc32(bytes)))) text += MINIMAL[byte];
  return text;
}

function fromBytewords(text) {
  if (text.length % 2 || text.length < 8) throw new Error('Damaged QR code.');
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = BYTE_OF.get(text.slice(2 * i, 2 * i + 2));
    if (byte === undefined) throw new Error('Damaged QR code.');
    bytes[i] = byte;
  }
  const body = bytes.subarray(0, -4);
  if (!bytes.subarray(-4).every((byte, i) => byte === uint32(crc32(body))[i])) throw new Error('Damaged QR code.');
  return body;
}

// ---------------------------------------------------------------- CBOR (the little of it that is needed)

function cborHead(major, value) {
  const type = major << 5;
  if (value < 24) return Uint8Array.of(type | value);
  if (value < 0x100) return Uint8Array.of(type | 24, value);
  if (value < 0x10000) return Uint8Array.of(type | 25, value >>> 8, value & 255);
  return concat(Uint8Array.of(type | 26), uint32(value));
}

// Reads one head of the given major type; returns its value and what follows.
function cborRead(bytes, major) {
  if (!bytes.length || bytes[0] >> 5 !== major) throw new Error('Unexpected QR code content.');
  const info = bytes[0] & 31;
  if (info < 24) return [info, bytes.subarray(1)];
  const size = { 24: 1, 25: 2, 26: 4 }[info];
  if (!size || bytes.length < 1 + size) throw new Error('Unexpected QR code content.');
  let value = 0;
  for (let i = 1; i <= size; i++) value = value * 256 + bytes[i];
  return [value, bytes.subarray(1 + size)];
}

function cborBytes(bytes) {
  const [length, rest] = cborRead(bytes, 2);
  if (rest.length < length) throw new Error('Unexpected QR code content.');
  return [rest.subarray(0, length), rest.subarray(length)];
}

// ---------------------------------------------------------------- fountain code

// Xoshiro256**, seeded as the UR specification prescribes.
function xoshiro(seed) {
  const digest = sha256(seed);
  const s = [0, 8, 16, 24].map((at) => digest.subarray(at, at + 8).reduce((v, byte) => (v << 8n) | BigInt(byte), 0n));
  const MASK = (1n << 64n) - 1n;
  const rotl = (x, k) => ((x << k) | (x >> (64n - k))) & MASK;
  const next = () => {
    const result = (rotl((s[1] * 5n) & MASK, 7n) * 9n) & MASK;
    const t = (s[1] << 17n) & MASK;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 45n);
    return result;
  };
  const double = () => Number(next()) / 2 ** 64;
  return { double, int: (low, high) => Math.floor(double() * (high - low + 1)) + low };
}

// Draws an index with the given weights (Vose's alias method).
function sampler(weights) {
  const n = weights.length;
  const sum = weights.reduce((a, b) => a + b, 0);
  const P = weights.map((weight) => (weight * n) / sum);
  const small = [];
  const large = [];
  for (let i = n - 1; i >= 0; i--) (P[i] < 1 ? small : large).push(i);
  const probs = new Array(n).fill(0);
  const aliases = new Array(n).fill(0);
  while (small.length && large.length) {
    const a = small.pop();
    const g = large.pop();
    probs[a] = P[a];
    aliases[a] = g;
    P[g] += P[a] - 1;
    (P[g] < 1 ? small : large).push(g);
  }
  while (large.length) probs[large.pop()] = 1;
  while (small.length) probs[small.pop()] = 1;
  return (rng) => {
    const r1 = rng.double();
    const r2 = rng.double();
    const i = Math.floor(n * r1);
    return r2 < probs[i] ? i : aliases[i];
  };
}

// Which fragments of the message are XORed together in part `seqNum`.
function fragmentsOf(seqNum, seqLen, checksum) {
  if (seqNum <= seqLen) return [seqNum - 1];
  const rng = xoshiro(concat(uint32(seqNum), uint32(checksum)));
  const degree = sampler(Array.from({ length: seqLen }, (_, i) => 1 / (i + 1)))(rng) + 1;
  const remaining = Array.from({ length: seqLen }, (_, i) => i);
  const chosen = [];
  while (chosen.length < degree) chosen.push(remaining.splice(rng.int(0, remaining.length - 1), 1)[0]);
  return chosen;
}

// ---------------------------------------------------------------- reading

export const isUr = (text) => /^ur:/i.test(text.trim());

// Collects the parts of one UR as they are scanned, in any order.
export class UrReader {
  constructor() {
    this.result = null;
    this.message = null;
    this.simple = new Map();
    this.mixed = [];
  }

  // Takes one scanned code. Returns how much of the message is in, from 0
  // to 1; at 1, `result` holds the PSBT.
  receive(text) {
    const [type, ...rest] = text.trim().toLowerCase().slice(3).split('/');
    if (!TYPES.includes(type)) throw new Error(`This QR code holds "${type}", not a transaction (PSBT).`);
    if (rest.length === 1) {
      this.result = cborBytes(fromBytewords(rest[0]))[0];
      return 1;
    }
    if (rest.length !== 2 || !/^\d+-\d+$/.test(rest[0])) throw new Error('Unexpected QR code content.');

    let body = fromBytewords(rest[1]);
    if (body[0] !== 0x85) throw new Error('Unexpected QR code content.');
    body = body.subarray(1);
    let seqNum, seqLen, messageLen, checksum, data;
    [seqNum, body] = cborRead(body, 0);
    [seqLen, body] = cborRead(body, 0);
    [messageLen, body] = cborRead(body, 0);
    [checksum, body] = cborRead(body, 0);
    [data] = cborBytes(body);
    if (!seqLen || seqLen > 10000 || !data.length || messageLen > seqLen * data.length) throw new Error('Unexpected QR code content.');

    const message = { seqLen, messageLen, checksum, size: data.length };
    if (!this.message || Object.keys(message).some((key) => this.message[key] !== message[key])) {
      // A different transaction: start over.
      this.message = message;
      this.result = null;
      this.simple = new Map();
      this.mixed = [];
    }
    if (!this.result) this.reduce({ indexes: new Set(fragmentsOf(seqNum, seqLen, checksum)), data: Uint8Array.from(data) });
    return this.result ? 1 : Math.min(0.99, this.simple.size / seqLen);
  }

  // Strips the fragments already known out of a part, and whatever that
  // uncovers out of the parts kept for later.
  reduce(part) {
    const queue = [part];
    while (queue.length) {
      const current = queue.pop();
      for (const index of [...current.indexes]) {
        const known = this.simple.get(index);
        if (!known) continue;
        current.indexes.delete(index);
        for (let i = 0; i < known.length; i++) current.data[i] ^= known[i];
      }
      if (current.indexes.size === 0) continue;
      if (current.indexes.size > 1) {
        this.mixed.push(current);
        continue;
      }
      const [index] = current.indexes;
      this.simple.set(index, current.data);
      const waiting = this.mixed.filter((mixed) => mixed.indexes.has(index));
      this.mixed = this.mixed.filter((mixed) => !mixed.indexes.has(index));
      queue.push(...waiting);
    }
    if (this.simple.size === this.message.seqLen) this.finish();
  }

  finish() {
    const { seqLen, messageLen, checksum } = this.message;
    const message = concat(...Array.from({ length: seqLen }, (_, i) => this.simple.get(i))).subarray(0, messageLen);
    if (crc32(message) !== checksum) throw new Error('The scanned parts do not add up. Scan the sequence again.');
    this.result = cborBytes(message)[0];
  }
}

// ---------------------------------------------------------------- writing

// A PSBT as UR codes: one if it fits `fragmentSize` bytes, else a sequence
// to be shown in a loop. Upper case, which QR codes store compactly.
export function psbtToUr(psbt, fragmentSize = 200) {
  const message = concat(cborHead(2, psbt.length), psbt);
  if (message.length <= fragmentSize) return [`ur:crypto-psbt/${bytewords(message)}`.toUpperCase()];
  const seqLen = Math.ceil(message.length / fragmentSize);
  const size = Math.ceil(message.length / seqLen);
  const checksum = crc32(message);
  return Array.from({ length: seqLen }, (_, i) => {
    const fragment = new Uint8Array(size);
    fragment.set(message.subarray(i * size, (i + 1) * size));
    const part = concat(
      Uint8Array.of(0x85),
      cborHead(0, i + 1),
      cborHead(0, seqLen),
      cborHead(0, message.length),
      cborHead(0, checksum),
      cborHead(2, size),
      fragment,
    );
    return `ur:crypto-psbt/${i + 1}-${seqLen}/${bytewords(part)}`.toUpperCase();
  });
}
