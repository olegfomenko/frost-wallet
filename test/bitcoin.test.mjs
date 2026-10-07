import assert from 'node:assert/strict';
import { test } from 'node:test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import { HDKey } from '@scure/bip32';
import * as btc from '@scure/btc-signer';
import { sha256 } from '@noble/hashes/sha2.js';
import { account, analyzePsbt, deriveTaproot, descriptorChecksum, formatBtc, isSighashMessage, NETWORKS, psbtFromText } from '../web/bitcoin.js';
import { applyTweaks, inputFor, sighashFromPsbt } from './helpers/bitcoin.mjs';

// Any valid point serves as a group key here.
const GROUP = hex.encode(secp256k1.getPublicKey(hex.decode('1f'.repeat(32)), true));
const OTHER = hex.encode(secp256k1.getPublicKey(hex.decode('2e'.repeat(32)), true));

test('descriptor checksums match Bitcoin Core', () => {
  assert.equal(descriptorChecksum('raw(deadbeef)'), '89f8spxm');
  assert.equal(descriptorChecksum('pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)'), '8fhd9pwu');
});

test('the xpub is a master key that other software derives the same keys from', () => {
  for (const [network, versions] of [['mainnet', undefined], ['testnet', { private: 0x04358394, public: 0x043587cf }]]) {
    const wallet = account(GROUP, network);
    assert.match(wallet.xpub, network === 'mainnet' ? /^xpub/ : /^tpub/);
    const root = HDKey.fromExtendedKey(wallet.xpub, versions);
    assert.equal(root.depth, 0);
    assert.equal(hex.encode(root.publicKey), GROUP);
    assert.equal(root.fingerprint.toString(16).padStart(8, '0'), wallet.fingerprint);
    for (const [chain, index] of [[0, 0], [0, 7], [1, 0], [1, 2147483647]]) {
      const key = wallet.address(chain, index);
      const reference = root.derive(`m/${chain}/${index}`).publicKey;
      assert.equal(hex.encode(key.internalKey), hex.encode(reference.subarray(1)));
      // The address is the BIP 86 one for that internal key.
      assert.equal(key.address, btc.p2tr(key.internalKey, undefined, NETWORKS[network].params).address);
    }
    assert.match(wallet.descriptor, new RegExp(`^tr\\(${wallet.xpub}/<0;1>/\\*\\)#[a-z0-9]{8}$`));
  }
  assert.match(account(GROUP, 'regtest').address(0, 0).address, /^bcrt1p/);
  assert.throws(() => deriveTaproot(hex.decode(GROUP), [0x80000000]), /unhardened/);
});

test('the Taproot output key follows the BIP 86 test vector', () => {
  // BIP 86, first receiving address: internal key and address.
  const internal = hex.decode('02cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115');
  const key = deriveTaproot(internal, []);
  assert.equal(key.address, 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr');
  assert.equal(hex.encode(key.outputKey), 'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c');
});

test('the tweaks handed to the core lead from the group key to the output key', () => {
  for (const group of [GROUP, OTHER]) {
    for (const path of [[], [0, 0], [1, 5], [0, 123456]]) {
      const key = deriveTaproot(hex.decode(group), path);
      assert.equal(key.tweaks.length, path.length + 1);
      assert.equal(hex.encode(applyTweaks(hex.decode(group), key.tweaks)), hex.encode(key.outputKey));
    }
  }
});

function payment({ origin = true, foreign = false } = {}) {
  const wallet = account(GROUP);
  const tx = new btc.Transaction();
  tx.addInput(inputFor(wallet.address(0, 3), wallet.fingerprint, { txid: '11'.repeat(32), vout: 1, amount: 100000n, origin }));
  tx.addInput(inputFor(wallet.address(1, 0), wallet.fingerprint, { txid: '22'.repeat(32), amount: 50000n, origin }));
  if (foreign) tx.addInput(inputFor(account(OTHER).address(0, 0), account(OTHER).fingerprint, { txid: '33'.repeat(32), amount: 7000n }));
  tx.addOutputAddress('bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', 120000n);
  const change = wallet.address(1, 9);
  const out = { script: change.script, amount: 29000n };
  if (origin) {
    out.tapInternalKey = change.internalKey;
    out.tapBip32Derivation = [[change.internalKey, { hashes: [], der: { fingerprint: parseInt(wallet.fingerprint, 16), path: [1, 9] } }]];
  }
  tx.addOutput(out);
  return tx.toPSBT();
}

test('a payment is read as the wallet sees it', () => {
  const psbt = payment();
  const seen = analyzePsbt(psbt, GROUP);
  assert.deepEqual(seen.inputs.map((i) => [i.status, i.path, i.amount]), [['sign', [0, 3], 100000n], ['sign', [1, 0], 50000n]]);
  assert.equal(seen.inputs[0].txid, '11'.repeat(32));
  assert.equal(seen.inputs[0].vout, 1);
  assert.deepEqual(seen.outputs.map((o) => [o.ours, o.amount]), [[null, 120000n], ['change', 29000n]]);
  assert.equal(seen.outputs[0].address, 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr');
  assert.equal(seen.fee, 1000n);
  assert.equal(seen.spent, 120000n);
  assert.deepEqual(seen.warnings, []);

  // What is to be signed: the BIP 341 hash of each input, under the key
  // its tweaks lead to.
  assert.equal(seen.items.length, 2);
  seen.items.forEach((item, i) => {
    assert.equal(item.input, i);
    assert.equal(item.digest, hex.encode(sighashFromPsbt(psbt, i)));
    // The core signs the SHA-256 of the message it is given.
    assert.equal(hex.encode(sha256(hex.decode(item.message))), item.digest);
    assert.ok(isSighashMessage(item.message));
    assert.equal(item.key, hex.encode(applyTweaks(hex.decode(GROUP), item.tweaks)));
  });
  assert.notEqual(seen.items[0].digest, seen.items[1].digest);
});

test('inputs and change are recognised without key information in the PSBT', () => {
  const seen = analyzePsbt(payment({ origin: false }), GROUP);
  assert.deepEqual(seen.inputs.map((i) => [i.status, i.path]), [['sign', [0, 3]], ['sign', [1, 0]]]);
  assert.equal(seen.outputs[1].ours, 'change');
  assert.equal(seen.items.length, 2);
});

test('a claimed derivation is believed only if it leads to the script', () => {
  const wallet = account(GROUP);
  const real = wallet.address(0, 3);
  const tx = new btc.Transaction();
  // The entry claims our key, but the coin sits on someone else's script.
  const lie = inputFor(real, wallet.fingerprint, { txid: '11'.repeat(32), amount: 100000n });
  lie.witnessUtxo.script = account(OTHER).address(0, 0).script;
  delete lie.tapInternalKey;
  tx.addInput(lie);
  tx.addOutputAddress('bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', 90000n);
  const seen = analyzePsbt(tx.toPSBT(), GROUP);
  assert.equal(seen.inputs[0].status, 'foreign');
  assert.equal(seen.items.length, 0);
  assert.match(seen.warnings.join(' '), /None of the inputs/);
});

test('foreign inputs, another key and odd requests are reported', () => {
  const mixed = analyzePsbt(payment({ foreign: true }), GROUP);
  assert.deepEqual(mixed.inputs.map((i) => i.status), ['sign', 'sign', 'foreign']);
  assert.equal(mixed.items.length, 2);
  assert.match(mixed.warnings.join(' '), /Input 3 is not from this wallet/);
  // The hashes still cover the foreign input: they differ from the ones without it.
  assert.notEqual(mixed.items[0].digest, analyzePsbt(payment(), GROUP).items[0].digest);

  const stranger = analyzePsbt(payment(), OTHER);
  assert.equal(stranger.items.length, 0);
  assert.match(stranger.warnings.join(' '), /None of the inputs/);

  const wallet = account(GROUP);
  const tx = new btc.Transaction();
  tx.addInput({ ...inputFor(wallet.address(0, 0), wallet.fingerprint, { txid: '44'.repeat(32), amount: 10000n }), sighashType: btc.SigHash.NONE });
  tx.addOutputAddress('bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', 4000n);
  const odd = analyzePsbt(tx.toPSBT(), GROUP);
  assert.equal(odd.inputs[0].status, 'unsupported');
  assert.equal(odd.items.length, 0);
  assert.match(odd.warnings.join(' '), /does not cover the whole transaction/);
  assert.match(odd.warnings.join(' '), /more than 5%/);
});

// A PSBT that Bitcoin Core (regtest) built for the descriptor of GROUP: two
// coins of the wallet pay 0.75 BTC to another address, with change. Kept
// as a sample of what real wallet software sends, with what it should be
// read as. The hashes were checked against BIP 341 when it was recorded.
const SAMPLE = {
  descriptor: "tr(tpubD6NzVbkrYhZ4XgHkCEtfpuZPJDLaLPxu5ZBEtAbub9GcUX1mTS2t3eCnBXLhLLhedzpf4SbqmW17bXMFm78uFyTMFKTjQtYfLRaPbiTPptY/<0;1>/*)#x37t3d9l",
  psbt: "cHNidP8BALICAAAAAjvwWHmqSFu96HlYonyaBLQS7fPBfquf6ypWEu4BP0dEAQAAAAD9////Z/galCoTIjnwyj4aT4Ofwobi0sJatwIiNEEu6uyLQeoAAAAAAP3///8CRN/kAAAAAAAiUSCfUbGm79gVY9fTLELdwI/QkVnD3NJQiLr/vkS9J5MWasBoeAQAAAAAIlEgx23zajYZ3vIr4Wkacg+HpSQfMFWfZcp/49eGOF3gyhsAAAAAAAEBKwCHkwMAAAAAIlEgNihOTiUoXadMPtHWWaYMWPNvNJ+ARkEmWtMjUdVu/AUhFh2ncQrZbWKsabtZuNkMRRVtSvn0J8/pIh8m45b6TnSPDQD2vfi3AAAAAAAAAAABFyAdp3EK2W1irGm7WbjZDEUVbUr59CfP6SIfJuOW+k50jwABASuAw8kBAAAAACJRINLEWV5pbdhUdBn37yXF20RF4IMtiPs0ynIR5EiMuqm+IRYgjNxg7K3DfYeFckVKLthqv1C971ZY+wAWFJNzRUtuuw0A9r34twAAAAABAAAAARcgIIzcYOytw32HhXJFSi7Yar9Qve9WWPsAFhSTc0VLbrsAAQUgR1dBfqSpFEqhdRGoGunzWu2/zM8xeDg7lUyyaQy5CcMhB0dXQX6kqRRKoXURqBrp81rtv8zPMXg4O5VMsmkMuQnDDQD2vfi3AQAAAAAAAAAAAA==",
  inputs: [
    { status: 'sign', path: [0, 0], amount: 60000000n, address: "bcrt1pxc5yun399pw6wnp768t9nfsvtrek7dylspryzfj66v34r4twlszs7ccee3" },
    { status: 'sign', path: [0, 1], amount: 30000000n, address: "bcrt1p6tz9jhnfdhv9gaqe7lhjt3wmg3z7pqed3ranfjnjz8jy3r964xlqxyj9s8" },
  ],
  outputs: [
    { ours: 'change', path: [1, 0], amount: 14999364n, address: "bcrt1pnagmrfh0mq2k847n93pdmsy06zg4ns7u6fgg3whlhezt6funze4q88gkf0" },
    { ours: null, path: null, amount: 75000000n, address: "bcrt1pcaklx63kr800y2lpdyd8yru855jp7vz4naju5llr67rrsh0qegds26h6fq" },
  ],
  fee: 636n,
  items: [
    { input: 0, digest: "0bc3321945a55f9e8855bddb2f5ec434afe4694c8c89702e497426ee9d5f6bcf", key: "36284e4e25285da74c3ed1d659a60c58f36f349f804641265ad32351d56efc05" },
    { input: 1, digest: "d26b7fad26bcb464761e1e080cb5764636eec25892b2a81b5b89426817e7a42b", key: "d2c4595e696dd8547419f7ef25c5db4445e0832d88fb34ca7211e4488cbaa9be" },
  ],
};

test('a PSBT built by Bitcoin Core is read correctly', () => {
  assert.equal(account(GROUP, 'regtest').descriptor, SAMPLE.descriptor);
  const seen = analyzePsbt(psbtFromText(SAMPLE.psbt), GROUP, 'regtest');
  assert.deepEqual(seen.inputs.map(({ status, path, amount, address }) => ({ status, path, amount, address })), SAMPLE.inputs);
  assert.deepEqual(seen.outputs.map(({ ours, path, amount, address }) => ({ ours, path, amount, address })), SAMPLE.outputs);
  assert.equal(seen.fee, SAMPLE.fee);
  assert.equal(seen.spent, 75000000n);
  assert.deepEqual(seen.warnings, []);
  assert.deepEqual(seen.items.map(({ input, digest, key }) => ({ input, digest, key })), SAMPLE.items);
  for (const item of seen.items) assert.equal(hex.encode(sha256(hex.decode(item.message))), item.digest);
  assert.equal(isSighashMessage(hex.encode(new TextEncoder().encode('hello'))), false);
  // The tweaks given to the core lead to the key of each coin.
  for (const item of seen.items) assert.equal(hex.encode(applyTweaks(hex.decode(GROUP), item.tweaks)), item.key);
  // Under another key there is nothing to sign in it.
  assert.equal(analyzePsbt(psbtFromText(SAMPLE.psbt), OTHER, 'regtest').items.length, 0);
});

test('coins at legacy addresses of the key are recognised and not signed', () => {
  // What a wallet does that was given the xpub without the descriptor:
  // pay-to-public-key-hash addresses for the same keys.
  const wallet = account(GROUP);
  const key = wallet.address(0, 0);
  const legacy = btc.p2pkh(key.pubkey);
  assert.match(legacy.address, /^1/);
  const tx = new btc.Transaction();
  tx.addInput({ txid: '55'.repeat(32), index: 0, witnessUtxo: { script: legacy.script, amount: 50000n } });
  tx.addOutputAddress('bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', 30000n);
  tx.addOutput({ script: btc.p2wpkh(wallet.address(1, 3).pubkey).script, amount: 19000n });
  const seen = analyzePsbt(tx.toPSBT(), GROUP);
  assert.equal(seen.inputs[0].status, 'wrongtype');
  assert.deepEqual(seen.inputs[0].path, [0, 0]);
  assert.equal(seen.inputs[0].address, legacy.address);
  assert.equal(seen.items.length, 0);
  assert.equal(seen.outputs[1].unspendable, 'SegWit');
  assert.equal(seen.outputs[1].ours, null);
  assert.match(seen.warnings.join(' '), /set up with the xpub alone/);
  assert.match(seen.warnings.join(' '), /Output 2 pays to a SegWit address of this key/);
});

test('PSBTs are accepted as base64 or hex, and nothing else is', () => {
  const psbt = payment();
  assert.deepEqual(psbtFromText(Buffer.from(psbt).toString('base64')), psbt);
  assert.deepEqual(psbtFromText(`  ${hex.encode(psbt).toUpperCase()}\n`), psbt);
  assert.deepEqual(psbtFromText(Buffer.from(psbt).toString('base64').replace(/(.{40})/g, '$1\n')), psbt);
  assert.equal(psbtFromText('FRSTAQICQgSK84zgqxOysAD8lqNwNdyoTp9pk0ygAD'), null);
  assert.equal(psbtFromText('hello'), null);
  assert.equal(psbtFromText('deadbeef'), null);
  assert.throws(() => analyzePsbt(Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff, 1, 2, 3), GROUP), /not a transaction this wallet can read/);
});

test('amounts are written in BTC', () => {
  assert.equal(formatBtc(0n), '0.00000000');
  assert.equal(formatBtc(1n), '0.00000001');
  assert.equal(formatBtc(123456789012n), '1234.56789012');
  assert.equal(formatBtc(-1500n), '-0.00001500');
});
