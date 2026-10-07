// Pieces the Bitcoin tests share. The signature hash here is written out
// from BIP 341 on purpose: it checks the library the page uses against the
// specification rather than against itself.

import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '@scure/base';
import * as btc from '@scure/btc-signer';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const Point = secp256k1.Point;

export const concat = (...parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const le = (value, bytes) => Uint8Array.from({ length: bytes }, (_, i) => Number((BigInt(value) >> BigInt(8 * i)) & 255n));
const withLength = (bytes) => {
  if (bytes.length >= 253) throw new Error('script too long for this helper');
  return concat([bytes.length], bytes);
};
const tagged = (tag, message) => {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concat(tagHash, tagHash, message));
};

// BIP 341 signature hash for a key-path spend with SIGHASH_DEFAULT.
// `prevouts` are `{ txid (hex, as displayed), vout, amount, script, sequence }`.
export function taprootSighash({ version, lockTime, prevouts, outputs }, inputIndex) {
  const message = concat(
    [0x00], // epoch
    [0x00], // hash type
    le(version, 4),
    le(lockTime, 4),
    sha256(concat(...prevouts.map((p) => concat(hex.decode(p.txid).reverse(), le(p.vout, 4))))),
    sha256(concat(...prevouts.map((p) => le(p.amount, 8)))),
    sha256(concat(...prevouts.map((p) => withLength(p.script)))),
    sha256(concat(...prevouts.map((p) => le(p.sequence, 4)))),
    sha256(concat(...outputs.map((o) => concat(le(o.amount, 8), withLength(o.script))))),
    [0x00], // spend type: key path, no annex
    le(inputIndex, 4),
  );
  return tagged('TapSighash', message);
}

// The same hash, with the transaction read back out of a PSBT.
export function sighashFromPsbt(psbt, inputIndex) {
  const tx = btc.Transaction.fromPSBT(psbt, { allowUnknownOutputs: true });
  const prevouts = Array.from({ length: tx.inputsLength }, (_, i) => {
    const input = tx.getInput(i);
    return {
      txid: hex.encode(input.txid),
      vout: input.index,
      amount: input.witnessUtxo.amount,
      script: input.witnessUtxo.script,
      sequence: input.sequence ?? 0xffffffff,
    };
  });
  const outputs = Array.from({ length: tx.outputsLength }, (_, i) => tx.getOutput(i));
  return taprootSighash({ version: tx.version, lockTime: tx.lockTime, prevouts, outputs }, inputIndex);
}

// Applies key tweaks the way the core does (BIP 327): a plain tweak adds
// `t*G`; an x-only one first flips the key to an even y.
export function applyTweaks(pubkey, tweaks) {
  let Q = Point.fromBytes(pubkey);
  for (const { value, xonly } of tweaks) {
    if (xonly && Q.toBytes(true)[0] === 3) Q = Q.negate();
    Q = Q.add(Point.BASE.multiply(BigInt(`0x${value}`)));
  }
  return Q.toBytes(true).subarray(1);
}

// An input spending `key` (as returned by account.address), the way a
// wallet that knows the descriptor would write it.
export function inputFor(key, fingerprint, { txid, vout = 0, amount, origin = true }) {
  const input = { txid, index: vout, witnessUtxo: { script: key.script, amount } };
  if (origin) {
    input.tapInternalKey = key.internalKey;
    input.tapBip32Derivation = [[key.internalKey, { hashes: [], der: { fingerprint: parseInt(fingerprint, 16), path: key.path } }]];
  }
  return input;
}
