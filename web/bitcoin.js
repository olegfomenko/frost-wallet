// Bitcoin on top of the group key: an extended public key for it, the
// Taproot addresses derived from that, and what a transaction (PSBT) asks
// this key to sign.
//
// Nothing here touches a secret, and the core knows nothing of Bitcoin. A
// transaction is signed through the core's ordinary message signing, one
// input at a time: the core signs the SHA-256 of a message, and a Taproot
// signature hash is the SHA-256 of a message too (BIP 341's tagged hash), so
// the message handed to the core is exactly that one.

import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { hmac } from '@noble/hashes/hmac.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { base64, createBase58check, hex } from '@scure/base';
import * as btc from '@scure/btc-signer';

const Point = secp256k1.Point;
const ORDER = Point.Fn.ORDER;
const base58check = createBase58check(sha256);

export const NETWORKS = {
  mainnet: { label: 'Bitcoin', params: btc.NETWORK, xpubVersion: 0x0488b21e },
  testnet: { label: 'Testnet / Signet', params: btc.TEST_NETWORK, xpubVersion: 0x043587cf },
  regtest: { label: 'Regtest', params: { ...btc.TEST_NETWORK, bech32: 'bcrt' }, xpubVersion: 0x043587cf },
};

// A threshold key comes out of key generation with no chain code, so its
// extended public key needs one from somewhere. BIP 328 settles the same
// question for MuSig2 aggregate keys with a fixed, public constant; the same
// constant is used here, so that the xpub of a group key is what a BIP 328
// tool would make of that key.
export const CHAIN_CODE = hex.decode('868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965');

const HARDENED = 0x80000000;
const SIGHASH_DEFAULT = 0;
// How far the receive and change chains are searched for a script whose
// PSBT entry does not say which key it belongs to.
const SCAN_DEPTH = 100;

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};
const same = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);
const uint32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const toBig = (bytes) => BigInt(`0x${hex.encode(bytes)}`);
const hash160 = (bytes) => ripemd160(sha256(bytes));
// What a tagged hash is the SHA-256 of.
const taggedMessage = (tag, ...parts) => {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return concat(tagHash, tagHash, ...parts);
};
const taggedHash = (tag, ...parts) => sha256(taggedMessage(tag, ...parts));
const littleEndian = (value, bytes) => Uint8Array.from({ length: bytes }, (_, i) => Number((BigInt(value) >> BigInt(8 * i)) & 255n));
const compactSize = (n) => (n < 253 ? Uint8Array.of(n) : n < 0x10000 ? concat([253], littleEndian(n, 2)) : concat([254], littleEndian(n, 4)));
const withLength = (bytes) => concat(compactSize(bytes.length), bytes);

// The message whose SHA-256 is the BIP 341 signature hash of input `index`,
// for a key-path spend that signs the whole transaction (SIGHASH_DEFAULT).
// `inputs` are `{ txid (hex, as displayed), vout, amount, script, sequence }`.
function sighashMessage({ version, lockTime, inputs, outputs }, index) {
  return taggedMessage(
    'TapSighash',
    [0x00], // epoch
    [SIGHASH_DEFAULT],
    littleEndian(version, 4),
    littleEndian(lockTime, 4),
    sha256(concat(...inputs.map((input) => concat(hex.decode(input.txid).reverse(), littleEndian(input.vout, 4))))),
    sha256(concat(...inputs.map((input) => littleEndian(input.amount, 8)))),
    sha256(concat(...inputs.map((input) => withLength(input.script)))),
    sha256(concat(...inputs.map((input) => littleEndian(input.sequence, 4)))),
    sha256(concat(...outputs.map((output) => concat(littleEndian(output.amount, 8), withLength(output.script))))),
    [0x00], // key path, no annex
    littleEndian(index, 4),
  );
}

// ---------------------------------------------------------------- keys

// One step of BIP 32 public derivation. `tweak` is what was added to the
// parent key; the core applies the same tweak to the group key to sign.
function deriveChild(pubkey, chainCode, index) {
  if (!Number.isInteger(index) || index < 0 || index >= HARDENED) {
    throw new Error('Only unhardened derivation is possible from a public key.');
  }
  const mac = hmac(sha512, chainCode, concat(pubkey, uint32(index)));
  const tweak = mac.subarray(0, 32);
  const scalar = toBig(tweak);
  if (scalar === 0n || scalar >= ORDER) throw new Error('This derivation index is not usable.');
  const child = Point.fromBytes(pubkey).add(Point.BASE.multiply(scalar));
  if (child.is0()) throw new Error('This derivation index is not usable.');
  return { pubkey: child.toBytes(true), chainCode: mac.subarray(32), tweak };
}

// The key at `path` below the group key, as a key-path-only Taproot output
// (BIP 86 style: the internal key commits to no scripts).
export function deriveTaproot(groupPubkey, path, network = 'mainnet') {
  let key = { pubkey: groupPubkey, chainCode: CHAIN_CODE };
  const tweaks = [];
  for (const index of path) {
    key = deriveChild(key.pubkey, key.chainCode, index);
    tweaks.push({ value: hex.encode(key.tweak), xonly: false });
  }
  const internalKey = key.pubkey.subarray(1);
  const tapTweak = taggedHash('TapTweak', internalKey);
  const scalar = toBig(tapTweak);
  if (scalar >= ORDER) throw new Error('This key cannot be used for Taproot.');
  const output = Point.fromBytes(concat(Uint8Array.of(2), internalKey)).add(Point.BASE.multiply(scalar));
  if (output.is0()) throw new Error('This key cannot be used for Taproot.');
  const outputKey = output.toBytes(true).subarray(1);
  tweaks.push({ value: hex.encode(tapTweak), xonly: true });
  return {
    path,
    pubkey: key.pubkey,
    internalKey,
    outputKey,
    script: concat(Uint8Array.of(0x51, 0x20), outputKey),
    address: btc.Address(NETWORKS[network].params).encode({ type: 'tr', pubkey: outputKey }),
    // In the order the core must apply them to the group key.
    tweaks,
  };
}

// Checksum of an output descriptor (as in Bitcoin Core's descriptor.cpp).
export function descriptorChecksum(descriptor) {
  const INPUT = '0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';
  const CHECKSUM = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GENERATOR = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];
  const polymod = (c, value) => {
    const top = c >> 35n;
    c = ((c & 0x7ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) c ^= GENERATOR[i];
    return c;
  };
  let c = 1n;
  let group = 0;
  let count = 0;
  for (const char of descriptor) {
    const position = INPUT.indexOf(char);
    if (position < 0) throw new Error('Invalid character in descriptor.');
    c = polymod(c, position & 31);
    group = group * 3 + (position >> 5);
    if (++count === 3) {
      c = polymod(c, group);
      group = 0;
      count = 0;
    }
  }
  if (count > 0) c = polymod(c, group);
  for (let i = 0; i < 8; i++) c = polymod(c, 0);
  c ^= 1n;
  let out = '';
  for (let i = 0; i < 8; i++) out += CHECKSUM[Number((c >> BigInt(5 * (7 - i))) & 31n)];
  return out;
}

// The group key as a watch-only wallet: its extended public key, the
// descriptor of the addresses below it, and those addresses.
export function account(groupPubkeyHex, network = 'mainnet') {
  const pubkey = hex.decode(groupPubkeyHex);
  const fingerprint = hash160(pubkey).subarray(0, 4);
  // Depth 0, no parent, child number 0: a master key.
  const xpub = base58check.encode(
    concat(uint32(NETWORKS[network].xpubVersion), new Uint8Array(9), CHAIN_CODE, pubkey),
  );
  const body = `tr(${xpub}/<0;1>/*)`;
  return {
    network,
    fingerprint: hex.encode(fingerprint),
    xpub,
    // Both chains in one descriptor (BIP 389). The part after `#` is the
    // descriptor's checksum (BIP 380).
    descriptor: `${body}#${descriptorChecksum(body)}`,
    // chain 0 is for receiving, chain 1 for change
    address: (chain, index) => deriveTaproot(pubkey, [chain, index], network),
  };
}

// ---------------------------------------------------------------- transactions

const PSBT_MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff];
export const isPsbt = (bytes) => bytes.length > 5 && PSBT_MAGIC.every((byte, i) => bytes[i] === byte);

// A PSBT typed or pasted as hex or base64; null if the text is neither.
export function psbtFromText(text) {
  const clean = text.replace(/\s+/g, '');
  try {
    if (/^(?:[0-9a-f]{2})+$/i.test(clean)) {
      const bytes = hex.decode(clean.toLowerCase());
      if (isPsbt(bytes)) return bytes;
    }
    const padded = clean.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    if (/^[A-Za-z0-9+/]+$/.test(padded)) {
      const bytes = base64.decode(padded + '='.repeat((4 - (padded.length % 4)) % 4));
      if (isPsbt(bytes)) return bytes;
    }
  } catch {
    // Not a PSBT in either notation.
  }
  return null;
}

const parse = (psbt) => {
  try {
    // Read leniently: what is shown and what is signed is decided below.
    return btc.Transaction.fromPSBT(psbt, {
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
      allowLegacyWitnessUtxo: true,
      disableScriptCheck: true,
    });
  } catch (error) {
    throw new Error(`This is not a transaction this wallet can read: ${error.message}`);
  }
};

export const formatBtc = (sats) => {
  const negative = sats < 0n;
  const value = negative ? -sats : sats;
  return `${negative ? '-' : ''}${value / 100000000n}.${String(value % 100000000n).padStart(8, '0')}`;
};

// Looks at a transaction from the point of view of the group key: what goes
// in, what goes out, which inputs are this wallet's, and what exactly has
// to be signed for them.
export function analyzePsbt(psbt, groupPubkeyHex, network = 'mainnet') {
  const tx = parse(psbt);
  const group = hex.decode(groupPubkeyHex);
  const fingerprint = Number(toBig(hash160(group).subarray(0, 4)));
  const params = NETWORKS[network].params;
  const warnings = [];

  const describe = (script) => {
    try {
      return btc.Address(params).encode(btc.OutScript.decode(script));
    } catch {
      return script[0] === 0x6a ? 'Data (OP_RETURN)' : `Script ${hex.encode(script)}`;
    }
  };

  // Scripts of the first addresses on both chains, for entries that carry
  // no key information. Built on first use.
  let scanned = null;
  let scannedOther = null;
  const scanAll = () => {
    scanned = new Map();
    scannedOther = new Map();
    for (const chain of [0, 1]) {
      for (let index = 0; index < SCAN_DEPTH; index++) {
        const key = deriveTaproot(group, [chain, index], network);
        scanned.set(hex.encode(key.script), key);
        // The same key in the older address types. A wallet that was given
        // only the xpub, not the descriptor, hands these out.
        const keyHash = hash160(key.pubkey);
        const segwit = concat([0x00, 0x14], keyHash);
        for (const [kind, script] of [
          ['legacy', concat([0x76, 0xa9, 0x14], keyHash, [0x88, 0xac])],
          ['SegWit', segwit],
          ['nested SegWit', concat([0xa9, 0x14], hash160(segwit), [0x87])],
        ]) scannedOther.set(hex.encode(script), { kind, path: key.path });
      }
    }
  };
  const scan = (script) => {
    if (!scanned) scanAll();
    return scanned.get(hex.encode(script)) ?? null;
  };
  // A script of this wallet's key in an address type other than Taproot.
  // Such coins need an ECDSA signature, which a FROST key cannot make.
  const otherType = (script) => {
    if (!script) return null;
    if (!scanned) scanAll();
    return scannedOther.get(hex.encode(script)) ?? null;
  };

  // The key of this wallet that a script pays to, if any. A claimed
  // derivation is believed only if it leads to exactly that script.
  const owner = (script, derivations) => {
    if (!script || script.length !== 34 || script[0] !== 0x51 || script[1] !== 0x20) return null;
    for (const [, info] of derivations ?? []) {
      const { fingerprint: claimed, path } = info.der;
      if (claimed !== fingerprint || path.length > 8 || path.some((index) => index >= HARDENED)) continue;
      try {
        const key = deriveTaproot(group, path, network);
        if (same(key.script, script)) return key;
      } catch {
        // An unusable index: not ours.
      }
    }
    return scan(script);
  };

  const inputs = [];
  let totalIn = 0n;
  let amountsKnown = true;
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    const previous = input.witnessUtxo ?? input.nonWitnessUtxo?.outputs?.[input.index] ?? null;
    if (!previous) amountsKnown = false;
    else totalIn += previous.amount;
    const key = previous ? owner(previous.script, input.tapBip32Derivation) : null;
    const other = key || !previous ? null : otherType(previous.script);
    let status = key ? 'sign' : other ? 'wrongtype' : 'foreign';
    let note = other ? `It sits at a ${other.kind} address of this key (${`m/${other.path.join('/')}`}). Spending from it takes an ECDSA signature, and this wallet makes Taproot (Schnorr) signatures only.` : '';
    if (key) {
      if (input.finalScriptWitness?.length || input.tapKeySig) {
        status = 'signed';
      } else if ((input.sighashType ?? SIGHASH_DEFAULT) !== SIGHASH_DEFAULT) {
        status = 'unsupported';
        note = 'It asks for a signature that does not cover the whole transaction, which this wallet does not make.';
      } else if (input.tapMerkleRoot?.length || input.tapLeafScript?.length) {
        status = 'unsupported';
        note = 'It is to be spent through a script, which this wallet does not do.';
      }
    }
    inputs.push({
      index: i,
      txid: hex.encode(input.txid),
      vout: input.index,
      amount: previous ? previous.amount : null,
      sequence: input.sequence ?? 0xffffffff,
      address: previous ? describe(previous.script) : 'unknown',
      path: key ? key.path : other ? other.path : null,
      status,
      note,
      key,
      script: previous?.script ?? null,
    });
  }

  const outputs = [];
  let totalOut = 0n;
  for (let i = 0; i < tx.outputsLength; i++) {
    const output = tx.getOutput(i);
    totalOut += output.amount;
    const key = owner(output.script, output.tapBip32Derivation);
    outputs.push({
      index: i,
      amount: output.amount,
      script: output.script,
      address: describe(output.script),
      path: key ? key.path : null,
      // Chain 1 is the change chain.
      ours: key ? (key.path[0] === 1 ? 'change' : 'receive') : null,
      // Set when the output pays this key at an address it cannot spend from.
      unspendable: key ? null : (otherType(output.script)?.kind ?? null),
    });
  }

  // A Taproot signature commits to the amount and script of every input, so
  // all of them have to be known, and a lie about any of them only makes
  // the signature worthless.
  const toSign = inputs.filter((input) => input.status === 'sign');
  let items = [];
  if (toSign.length && !amountsKnown) {
    warnings.push('The transaction does not say what some of its inputs are worth, so nothing can be signed.');
  } else if (toSign.length) {
    const shape = { version: tx.version, lockTime: tx.lockTime, inputs, outputs };
    const scripts = inputs.map((input) => input.script);
    const amounts = inputs.map((input) => input.amount);
    items = toSign.map((input) => {
      const message = sighashMessage(shape, input.index);
      const digest = sha256(message);
      // Two independent computations of the hash have to agree: the one
      // above, and the transaction library's.
      if (!same(digest, tx.preimageWitnessV1(input.index, scripts, SIGHASH_DEFAULT, amounts))) {
        throw new Error('The signature hash of this transaction could not be established.');
      }
      return {
        input: input.index,
        // Handed to the core as the message to sign...
        message: hex.encode(message),
        // ...which signs its SHA-256: the signature hash of the input.
        digest: hex.encode(digest),
        tweaks: input.key.tweaks,
        key: hex.encode(input.key.outputKey),
      };
    });
  }

  const fee = amountsKnown ? totalIn - totalOut : null;
  const spent = outputs.filter((output) => !output.ours).reduce((sum, output) => sum + output.amount, 0n);
  if (inputs.some((input) => input.status === 'wrongtype')) {
    warnings.push('This transaction spends from addresses of this key that are not Taproot addresses. They come from a wallet that was set up with the xpub alone; set it up with the descriptor instead. This wallet cannot sign for them.');
  } else if (!inputs.some((input) => input.key)) {
    warnings.push('None of the inputs belongs to this group key. Check the network and the key.');
  }
  outputs.forEach((output, i) => {
    if (output.unspendable) warnings.push(`Output ${i + 1} pays to a ${output.unspendable} address of this key. This wallet could not spend from it.`);
  });
  for (const input of inputs) {
    if (input.status === 'unsupported' || input.status === 'wrongtype') warnings.push(`Input ${input.index + 1} will not be signed. ${input.note}`);
    if (input.status === 'foreign' && toSign.length) warnings.push(`Input ${input.index + 1} is not from this wallet and will not be signed.`);
  }
  if (fee !== null && fee < 0n) warnings.push('The outputs are worth more than the inputs: this transaction is not valid.');
  if (fee !== null && totalIn > 0n && fee * 20n > totalIn) warnings.push(`The fee is more than 5% of what is being spent (${formatBtc(fee)} BTC).`);

  return {
    inputs: inputs.map(({ key, script, sequence, ...input }) => input),
    outputs: outputs.map(({ script, ...output }) => output),
    totalIn: amountsKnown ? totalIn : null,
    totalOut,
    spent,
    fee,
    items,
    warnings,
  };
}

// Puts finished signatures into the transaction: `signatures` maps the
// index of an input to its signature (hex). Every signature is checked here
// once more, independently of the core, against the hash and key it is for.
export function finalizePsbt(psbt, items, signatures) {
  const tx = parse(psbt);
  for (const item of items) {
    if (!(item.input in signatures)) continue;
    const signature = hex.decode(signatures[item.input]);
    if (!schnorr.verify(signature, hex.decode(item.digest), hex.decode(item.key))) {
      throw new Error(`The signature for input ${item.input + 1} is not valid.`);
    }
    tx.updateInput(item.input, { tapKeySig: signature }, true);
    tx.finalizeIdx(item.input);
  }
  const complete = tx.isFinal;
  return {
    psbt: tx.toPSBT(),
    complete,
    // Ready to broadcast only when every input is signed.
    tx: complete ? hex.encode(tx.extract()) : null,
    txid: complete ? tx.id : null,
  };
}

// Whether a message is the signature hash message of some Taproot input,
// whatever the transaction.
const TAP_SIGHASH_PREFIX = hex.encode(taggedMessage('TapSighash'));
export const isSighashMessage = (messageHex) => messageHex.startsWith(TAP_SIGHASH_PREFIX);
