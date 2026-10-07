// The whole way through: a group key made by the WebAssembly core, a
// transaction spending from its addresses, signing by a quorum, and a
// finished transaction whose signatures are checked against BIP 341 and
// BIP 340 by code that shares nothing with the wallet.
//
// Needs the core built (`npm run build`, which `npm test` runs first).

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { schnorr } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import * as btc from '@scure/btc-signer';
import { account, analyzePsbt, finalizePsbt } from '../web/bitcoin.js';
import { loadCore } from '../web/core.js';
import { psbtToUr, UrReader } from '../web/ur.js';
import { inputFor, sighashFromPsbt } from './helpers/bitcoin.mjs';

const wasm = readFileSync(new URL('../target/wasm32-unknown-unknown/release/frost_wallet_core.wasm', import.meta.url));

// One device: its own instance of the core.
async function device(role) {
  const core = await loadCore(wasm);
  const call = (request) => {
    const response = core(request);
    if (!response.ok) throw new Error(response.error);
    return response;
  };
  call({ op: 'set_role', role });
  return { call, import: (data) => call({ op: 'import', data }), state: () => call({ op: 'state' }).state };
}

async function keygen(n, t) {
  const coordinator = await device('coordinator');
  const participants = await Promise.all(Array.from({ length: n }, () => device('participant')));
  for (const p of participants) coordinator.import(p.call({ op: 'p_new_host' }).state.host.out.data);
  const params = coordinator.call({ op: 'c_dkg_start', t }).state.dkg.params.data;
  let reply;
  for (const p of participants) {
    p.import(params);
    reply = coordinator.import(p.call({ op: 'p_dkg_join' }).state.dkg.out.data);
  }
  const round1 = reply.state.dkg.out1.data;
  for (const p of participants) reply = coordinator.import(p.import(round1).state.dkg.out.data);
  const certificate = reply.state.dkg.out2.data;
  for (const p of participants) p.import(certificate);
  return { coordinator, participants, group: coordinator.state().group.pubkey };
}

// A transaction is signed the way the page does it: one ordinary message
// session per input. The core is told nothing about Bitcoin; the message it
// is given is the one whose SHA-256 is the input's signature hash.
function signTransaction({ coordinator, participants, group }, psbt, signers) {
  const seen = analyzePsbt(psbt, group);
  const signatures = {};
  for (const item of seen.items) {
    const request = coordinator.call({ op: 'c_sign_start', msg: item.message, tweaks: item.tweaks }).state.sign.request.data;
    for (const i of signers) {
      // A signer reads the transaction for itself and finds the request in it.
      const asked = participants[i].import(request).state.sign;
      const own = analyzePsbt(psbt, group).items.find((candidate) => candidate.message === asked.msg.hex);
      assert.ok(own, 'the request is for an input of the transaction');
      assert.equal(asked.msg.digest, own.digest);
      assert.equal(asked.key, own.key);
      coordinator.import(participants[i].call({ op: 'p_sign_approve' }).state.sign.out.data);
    }
    const pkg = coordinator.call({ op: 'c_sign_package' }).state.sign.package.data;
    let done;
    for (const i of signers) done = coordinator.import(participants[i].import(pkg).state.sign.out.data);
    assert.equal(done.state.sign.stage, 'done');
    signatures[item.input] = done.state.sign.signature.sig;
    coordinator.call({ op: 'c_sign_abort' });
    for (const i of signers) participants[i].call({ op: 'p_sign_abort' });
  }
  return { seen, signatures };
}

test('a transaction with several inputs is signed by a quorum and is valid', async () => {
  const session = await keygen(3, 2);
  const wallet = account(session.group);

  const tx = new btc.Transaction();
  tx.addInput(inputFor(wallet.address(0, 0), wallet.fingerprint, { txid: 'aa'.repeat(32), vout: 2, amount: 250000n }));
  tx.addInput(inputFor(wallet.address(1, 4), wallet.fingerprint, { txid: 'bb'.repeat(32), amount: 80000n }));
  tx.addInput(inputFor(wallet.address(0, 17), wallet.fingerprint, { txid: 'cc'.repeat(32), vout: 1, amount: 4000n }));
  tx.addOutputAddress('bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', 300000n);
  tx.addOutput({ script: wallet.address(1, 5).script, amount: 33000n });
  const psbt = tx.toPSBT();

  const { seen, signatures } = signTransaction(session, psbt, [0, 2]);
  assert.deepEqual(Object.keys(signatures), ['0', '1', '2']);
  assert.equal(seen.fee, 1000n);

  const result = finalizePsbt(psbt, seen.items, signatures);
  assert.equal(result.complete, true);

  // The finished transaction, read back with nothing but the library's
  // parser: each witness is one 64-byte signature that verifies under the
  // output key of the coin it spends, over the BIP 341 hash computed here.
  const final = btc.Transaction.fromRaw(hex.decode(result.tx), { allowUnknownOutputs: true });
  assert.equal(final.id, result.txid);
  assert.equal(final.inputsLength, 3);
  const spent = [wallet.address(0, 0), wallet.address(1, 4), wallet.address(0, 17)];
  for (let i = 0; i < 3; i++) {
    const witness = final.getInput(i).finalScriptWitness;
    assert.equal(witness.length, 1);
    assert.equal(witness[0].length, 64);
    assert.ok(schnorr.verify(witness[0], sighashFromPsbt(psbt, i), spent[i].outputKey), `input ${i} verifies`);
    // And not under the bare group key: the tweaks were really applied.
    assert.ok(!schnorr.verify(witness[0], sighashFromPsbt(psbt, i), hex.decode(session.group).subarray(1)));
  }
  assert.equal(final.getOutput(0).amount, 300000n);

  // The signed PSBT survives the trip back to another wallet as QR codes.
  const reader = new UrReader();
  for (const part of psbtToUr(result.psbt, 120)) reader.receive(part);
  assert.deepEqual(reader.result, result.psbt);
  assert.ok(btc.Transaction.fromPSBT(reader.result, { allowUnknownOutputs: true }).isFinal);
});

test('a transaction that also spends coins of another wallet stays incomplete', async () => {
  const session = await keygen(2, 2);
  const wallet = account(session.group);
  const other = account('02' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');

  const tx = new btc.Transaction();
  tx.addInput(inputFor(wallet.address(0, 1), wallet.fingerprint, { txid: 'dd'.repeat(32), amount: 60000n }));
  tx.addInput(inputFor(other.address(0, 0), other.fingerprint, { txid: 'ee'.repeat(32), amount: 60000n }));
  tx.addOutputAddress('bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', 119000n);
  const psbt = tx.toPSBT();

  const { seen, signatures } = signTransaction(session, psbt, [0, 1]);
  assert.deepEqual(seen.inputs.map((input) => input.status), ['sign', 'foreign']);
  assert.deepEqual(Object.keys(signatures), ['0']);
  const result = finalizePsbt(psbt, seen.items, signatures);
  assert.equal(result.complete, false);
  assert.equal(result.tx, null);

  // Our half is in the PSBT, valid, and read as already signed next time.
  const again = analyzePsbt(result.psbt, session.group);
  assert.deepEqual(again.inputs.map((input) => input.status), ['signed', 'foreign']);
  assert.equal(again.items.length, 0);
});

test('a signature that does not fit the transaction is refused when it is put in', async () => {
  const session = await keygen(2, 2);
  const wallet = account(session.group);
  const build = (amount) => {
    const tx = new btc.Transaction();
    tx.addInput(inputFor(wallet.address(0, 0), wallet.fingerprint, { txid: 'ff'.repeat(32), amount: 50000n }));
    tx.addOutputAddress('bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', amount);
    return tx.toPSBT();
  };
  const { signatures } = signTransaction(session, build(49000n), [0, 1]);
  // The same signature, offered for a transaction that pays a different amount.
  const altered = build(48000n);
  assert.throws(() => finalizePsbt(altered, analyzePsbt(altered, session.group).items, signatures), /not valid/);
});
