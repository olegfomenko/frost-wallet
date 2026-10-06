import { decodeQr, encodeQr } from './qr.js';

// The page as it was loaded, taken before anything here touches the document,
// so that it can be saved again from the page itself. The file is laid out
// the way the browser serialises it, which makes this an exact copy.
const PAGE_SOURCE = `<!doctype html>\n${document.documentElement.outerHTML}\n`;

// The page is a thin view over the WebAssembly core. Every action is a JSON
// request to the core; every response carries the state snapshot `S` that
// the views below render. Payloads travel as one base64 string, whether they
// are shown as a QR code, copied as text or saved as a file.

// Filled in by the build.
const VERSION = __VERSION__;
const WASM_SHA256 = __WASM_SHA256__;
const MAGIC = [0x15, 0x14, 0x93];
const PART = /^frostqr:(\d{1,3})\/(\d{1,3}):([A-Za-z0-9+/]{6}):([A-Za-z0-9+/]+)$/;
// Characters of payload per QR symbol before it is split into a sequence.
const DENSITY = { low: 220, mid: 420, high: 900 };

const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const no = (idx) => `#${idx + 1}`;

let wasm = null;
let S = { role: null };
let outs = [];
let timers = [];
const qrCache = new Map();

// A message being entered: one value, written in the selected notation.
const MODES = [['text', 'Text'], ['hex', 'Hex'], ['base64', 'Base64']];
const newDraft = () => ({ mode: 'text', value: '', tweaks: '' });

const ui = {
  tab: null,
  outMode: 'qr',
  density: 'mid',
  reveal: {},
  t: null,
  msgView: 'text',
  msgOpen: false,
  draft: newDraft(),
  verify: { ...newDraft(), pubkey: '', sig: '' },
};

const sheet = { open: false, mode: 'paste', hint: '', seen: new Set(), done: new Set(), asm: null };
const cam = { stream: null, timer: 0, last: '', lastAt: 0, canvas: document.createElement('canvas') };

// ---------------------------------------------------------------- core bridge

async function boot() {
  const b64 = $('#wasm').textContent.trim();
  const { instance } = await WebAssembly.instantiate(fromBase64(b64), {
    env: {
      fw_random(ptr, len) {
        crypto.getRandomValues(new Uint8Array(wasm.memory.buffer, ptr, len));
      },
    },
  });
  wasm = instance.exports;
  call({ op: 'state' });
  render();
}

function put(bytes) {
  const ptr = wasm.fw_alloc(bytes.length);
  new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

// Copies a result out of the module's memory, then wipes and frees it there.
function take(packed) {
  const ptr = Number(packed >> 32n);
  const len = Number(packed & 0xffffffffn);
  const view = new Uint8Array(wasm.memory.buffer, ptr, len);
  const copy = view.slice();
  view.fill(0);
  wasm.fw_free(ptr, len);
  return copy;
}

function call(req) {
  const bytes = enc.encode(JSON.stringify(req));
  const res = JSON.parse(dec.decode(take(wasm.fw_call(put(bytes), bytes.length))));
  bytes.fill(0);
  if (res.state) S = res.state;
  if (!res.ok) throw new Error(res.error);
  return res.result;
}

// ---------------------------------------------------------------- bytes

function fromBase64(text) {
  const bin = atob(text);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function toBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function fromHex(text, what) {
  const clean = text.replace(/\s+/g, '').replace(/^0x/i, '');
  if (!clean || clean.length % 2 || /[^0-9a-f]/i.test(clean)) {
    throw new Error(`${what} is not valid hex.`);
  }
  return Uint8Array.from(clean.match(/../g), (pair) => parseInt(pair, 16));
}

function formatBytes(n) {
  return n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`;
}

// ---------------------------------------------------------------- icons

const icon = (paths) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
const ICON = {
  logo: `<svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#0b1220"/><g stroke="#7cc4ff" stroke-width="2.2" stroke-linecap="round" fill="none"><path d="M16 6v20M7.3 11l17.4 10M7.3 21l17.4-10"/><path d="M13.5 7.5 16 10l2.5-2.5M13.5 24.5 16 22l2.5 2.5"/></g></svg>`,
  key: icon('<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M16 7l3 3M14 9l2 2"/>'),
  hub: icon('<circle cx="12" cy="12" r="3"/><circle cx="5" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="m6.5 6.5 3.3 3.3M17.5 6.5l-3.3 3.3M6.5 17.5l3.3-3.3M17.5 17.5l-3.3-3.3"/>'),
  down: icon('<path d="M12 4v11M7 11l5 5 5-5M5 20h14"/>'),
  ok: icon('<circle cx="12" cy="12" r="9"/><path d="m8 12.5 2.8 2.8L16 9.5"/>'),
  bad: icon('<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>'),
};

// ---------------------------------------------------------------- building blocks

const importBtn = (label, hint, primary = true) =>
  `<button class="btn ${primary ? 'primary' : ''}" data-act="import" data-hint="${esc(hint)}">${ICON.down}${esc(label)}</button>`;

const kv = (label, value, copy = true) =>
  `<div><dt>${esc(label)}</dt><dd><span class="mono">${esc(value)}</span>${
    copy ? `<button class="btn mini" data-act="copy" data-val="${esc(value)}">Copy</button>` : ''
  }</dd></div>`;

const steps = (labels, current) =>
  `<ol class="steps">${labels
    .map((label, i) => `<li class="${i < current ? 'done' : i === current ? 'now' : ''}">${i + 1}. ${esc(label)}</li>`)
    .join('')}</ol>`;

// A payload to hand over: rendered by mountOut as QR code, text or file.
function outBox(out, secret = false) {
  outs.push({ out, secret });
  return `<div class="out" data-out="${outs.length - 1}"></div>`;
}

function people(hosts, mark) {
  return `<ul class="people">${hosts
    .map((host, i) => `<li><span class="num">${no(i)}</span><span class="fp">${esc(host.fp)}</span>${mark(host, i)}</li>`)
    .join('')}</ul>`;
}

function groupCard(group, title = 'Group key') {
  return `<section class="card">
    <div class="head"><h2>${esc(title)}</h2><span class="chip accent">${group.t}-of-${group.n}</span>${
      group.idx === undefined ? '' : `<span class="chip">you are ${no(group.idx)}</span>`
    }</div>
    <dl class="kv">
      ${kv('Fingerprint', group.fp, false)}
      ${kv('Public key (BIP340 x-only)', group.xonly)}
      ${kv('Compressed public key', group.pubkey)}
    </dl>
  </section>`;
}

// A received message, shown raw in the notation the reader picks.
function messageBlock(msg) {
  const view = ui.msgView === 'text' && msg.text === null ? 'hex' : ui.msgView;
  const seg = MODES.map(([mode, label]) =>
    `<button data-act="msg-view" data-mode="${mode}" aria-pressed="${view === mode}"${
      mode === 'text' && msg.text === null ? ' disabled title="These bytes are not readable text"' : ''
    }>${label}</button>`).join('');
  const value = msg[view];
  return `<div class="field"><div class="head"><span class="label">Message · ${formatBytes(msg.len)}</span><div class="seg">${seg}</div></div>
    <div class="msgbox ${view === 'text' ? '' : 'mono'}">${esc(value || '(empty)')}</div>
    <div class="row"><button class="btn mini" data-act="copy" data-val="${esc(value)}">Copy ${view}</button></div></div>
    <dl class="kv">${kv('SHA-256 digest of the message — this is what gets signed', msg.digest)}</dl>`;
}

// Entry of a raw message as text, hex or base64. The wallet hashes it itself.
function messageInput(group) {
  const d = ui[group];
  const seg = MODES.map(([mode, label]) =>
    `<button data-act="msg-mode" data-group="${group}" data-mode="${mode}" aria-pressed="${d.mode === mode}">${label}</button>`).join('');
  const hint = { text: 'The message as plain text', hex: 'The message bytes in hex', base64: 'The message bytes in base64' }[d.mode];
  return `<div class="field"><div class="head"><span class="label">Message</span><div class="seg">${seg}</div></div>
    <textarea rows="4" class="${d.mode === 'text' ? '' : 'mono'}" data-bind="${group}.value" placeholder="${hint}" spellcheck="false" autocomplete="off" autocapitalize="off">${esc(d.value)}</textarea>
    <span class="muted small">Enter the raw message. The wallet always signs and verifies its SHA-256 digest.</span></div>`;
}

function tweakList(tweaks) {
  if (!tweaks.length) return '';
  return `<div class="note warn"><b>Tweaked key.</b> The signature will verify under the group key with ${tweaks.length} tweak${tweaks.length > 1 ? 's' : ''} applied:
    <div class="mono">${tweaks.map((t) => `${t.xonly ? 'xonly' : 'plain'}:${esc(t.value)}`).join('<br>')}</div></div>`;
}

const failure = (error, op) =>
  `<div class="note danger"><b>Session failed.</b> ${esc(error || 'Unknown error.')}</div>
   <div class="row"><button class="btn" data-act="do" data-op="${op}">Discard session</button></div>`;

// ---------------------------------------------------------------- views

function viewRoles() {
  return `<main>
    <div class="hero">
      <h1>Threshold keys,<br>kept off the network.</h1>
      <p>Generate a FROST threshold key with ChillDKG and co-sign with it, passing every message by QR code, text or file. Choose what this device does.</p>
    </div>
    <div class="roles">
      <button class="role" data-act="role" data-role="participant">${ICON.key}<strong>Participant</strong>
        <span>Holds one share of the key. Takes part in key generation, approves and co-signs messages, keeps its own backups.</span><em>Holds secrets</em></button>
      <button class="role" data-act="role" data-role="coordinator">${ICON.hub}<strong>Coordinator</strong>
        <span>Collects the participants' messages, relays the combined ones back and assembles the final signature.</span><em>Holds no secrets</em></button>
    </div>
    <section class="card flat"><p class="small muted">Every device runs this same file. Nothing is stored: closing the tab wipes the session, so back up what you need before you leave. For real keys, use it on a device that is offline.</p></section>
  </main>`;
}

function viewIdentity() {
  const host = S.host;
  if (!host) {
    return `<section class="card">
      <h2>Create your identity</h2>
      <p>A <b>host key</b> identifies this device during key generation, and later lets you recover your key share from public recovery data. Create it once and back it up.</p>
      <div class="row"><button class="btn primary" data-act="do" data-op="p_new_host">Create host key</button>
      ${importBtn('Restore from backup', 'Import a host secret key backup or a key share backup.', false)}</div>
    </section>`;
  }
  return `<section class="card">
      <div class="head"><h2>Host key</h2><span class="chip accent">${esc(host.fp)}</span></div>
      <dl class="kv">${kv('Host public key', host.pubkey)}</dl>
    </section>
    <section class="card">
      <h2>Send your host public key to the coordinator</h2>
      <p class="muted small">The coordinator needs it from every participant before key generation can start.</p>
      ${outBox(host.out)}
    </section>
    ${secretCard('host_secret', 'Back up the host secret key',
      'Together with the public recovery data, this key restores your share of every key it took part in. Anyone who gets it can do the same.')}
    <div class="row end"><button class="btn danger quiet" data-act="confirm" data-op="p_forget_host"
      data-ask="Forget the host key on this device? Without a backup it cannot be restored.">Forget host key</button></div>`;
}

function secretCard(what, title, text) {
  const shown = ui.reveal[what];
  return `<section class="card secret">
    <div class="head"><h2>${esc(title)}</h2><span class="chip warn">secret</span></div>
    <p class="small">${esc(text)}</p>
    ${shown
      ? `${outBox(shown, true)}<div class="row"><button class="btn" data-act="hide" data-what="${what}">Hide</button></div>`
      : `<div class="row"><button class="btn" data-act="reveal" data-what="${what}">Reveal backup</button></div>`}
  </section>`;
}

function viewKeygenParticipant() {
  const d = S.dkg;
  const labels = ['Join', 'Round 1', 'Round 2', 'Done'];
  if (!d) {
    if (S.group) {
      return `${groupCard(S.group, 'Your group key')}
        <section class="card flat"><p class="small muted">This device already holds a key share. To generate a different key, forget this one on the Backup tab first.</p></section>`;
    }
    if (!S.host) {
      return `<section class="card"><h2>No identity yet</h2><p>Create or restore your host key first.</p>
        <div class="row"><button class="btn primary" data-act="tab" data-tab="identity">Go to Identity</button></div></section>`;
    }
    return `<section class="card">${steps(labels, 0)}
      <h2>Waiting for the session parameters</h2>
      <p>Once the coordinator has every participant's host public key, they send out the session parameters. Import them here.</p>
      <div class="row">${importBtn('Import parameters', 'Import the key generation parameters from the coordinator.')}</div>
    </section>`;
  }
  if (d.stage === 'failed') {
    return `<section class="card"><h2>Key generation</h2>${failure(d.error, 'p_dkg_abort')}
      <p class="small muted">A failed session cannot be resumed. Every participant has to start again with new parameters.</p></section>`;
  }
  if (d.stage === 'review') {
    return `<section class="card">${steps(labels, 0)}
      <div class="head"><h2>Join this key generation?</h2><span class="chip accent">${d.t}-of-${d.n}</span></div>
      <p>Any <b>${d.t}</b> of these <b>${d.n}</b> participants will be able to sign. Compare the fingerprints with the other participants over a channel you trust before joining.</p>
      ${people(d.hosts, (_, i) => (i === d.idx ? '<span class="chip good">you</span>' : ''))}
      <div class="row"><button class="btn primary" data-act="do" data-op="p_dkg_join">Join key generation</button>
      <button class="btn quiet" data-act="do" data-op="p_dkg_abort">Decline</button></div>
    </section>`;
  }
  if (d.stage === 'round1' || d.stage === 'round2') {
    const second = d.stage === 'round2';
    return `<section class="card">${steps(labels, second ? 2 : 1)}
      <div class="head"><h2>Send your round ${second ? 2 : 1} message to the coordinator</h2><span class="chip">you are ${no(d.idx)}</span></div>
      ${outBox(d.out)}
    </section>
    <section class="card">
      <h2>${second ? 'Then import the certificate' : "Then import the coordinator's reply"}</h2>
      <p class="muted small">${second
        ? 'The coordinator sends it once every participant has confirmed the session. It completes your key share.'
        : 'The coordinator sends it once all round 1 messages are in.'}</p>
      <div class="row">${importBtn(second ? 'Import certificate' : 'Import reply',
        second ? 'Import the key generation certificate from the coordinator.' : "Import the coordinator's round 1 message.")}
      <button class="btn danger quiet" data-act="confirm" data-op="p_dkg_abort" data-ask="Abort this key generation session? It cannot be resumed.">Abort</button></div>
      <div class="note warn">Keep this tab open until key generation is done. The session lives only in memory.</div>
    </section>`;
  }
  return `<section class="card">${steps(labels, 4)}
      <div class="note good"><b>Key generation complete.</b> You hold share ${no(d.idx)} of a ${d.t}-of-${d.n} key.</div>
      <p>Back up your key share now: it exists only in this tab.</p>
      <div class="row"><button class="btn primary" data-act="tab" data-tab="backup">Go to Backup</button></div>
    </section>${S.group ? groupCard(S.group, 'Your group key') : ''}`;
}

function viewKeygenCoordinator() {
  const d = S.dkg;
  const labels = ['Participants', 'Round 1', 'Round 2', 'Done'];
  if (!d) {
    if (S.group) {
      return `${groupCard(S.group)}
        <section class="card flat"><p class="small muted">A group key is loaded. To run a new key generation, forget it on the Backup tab first.</p></section>`;
    }
    const n = S.roster.length;
    const t = Math.min(Math.max(ui.t ?? Math.floor(n / 2) + 1, 1), Math.max(n, 1));
    return `<section class="card">${steps(labels, 0)}
      <div class="head"><h2>Participants</h2><span class="chip">${n} added</span></div>
      <p class="muted small">Import the host public key of every participant. The order here is their number in the group.</p>
      ${n ? people(S.roster, (_, i) => `<button class="btn mini" data-act="do" data-op="c_roster_remove" data-index="${i}">Remove</button>`) : ''}
      <div class="row">${importBtn('Import host public key', "Import a participant's host public key.", n === 0)}</div>
    </section>
    ${n ? `<section class="card">
      <h2>Threshold</h2>
      <div class="row"><input type="number" inputmode="numeric" min="1" max="${n}" value="${t}" data-bind="t" aria-label="Threshold">
        <span>of ${n} participant${n > 1 ? 's' : ''} must co-sign.</span></div>
      <div class="row"><button class="btn primary" data-act="dkg-start">Start key generation</button></div>
    </section>` : ''}`;
  }
  const abort = `<button class="btn danger quiet" data-act="confirm" data-op="c_dkg_abort" data-ask="Abort this key generation session? Every participant will have to start again.">Abort</button>`;
  const progress = (got) => people(d.hosts, (_, i) => (got[i] ? '<span class="chip good">received</span>' : '<span class="chip">waiting</span>'));
  if (d.stage === 'failed') {
    return `<section class="card"><h2>Key generation</h2>${failure(d.error, 'c_dkg_abort')}
      <p class="small muted">A failed session cannot be resumed. Start a new one; leave out a participant that was named as faulty.</p></section>`;
  }
  if (d.stage === 'round1') {
    return `<section class="card">${steps(labels, 1)}
      <div class="head"><h2>Send the parameters to every participant</h2><span class="chip accent">${d.t}-of-${d.n}</span></div>
      ${outBox(d.params)}
    </section>
    <section class="card">
      <h2>Collect the round 1 messages</h2>
      ${progress(d.got1)}
      <div class="row">${importBtn('Import round 1 message', "Import a participant's round 1 message.")}${abort}</div>
    </section>`;
  }
  if (d.stage === 'round2') {
    return `<section class="card">${steps(labels, 2)}
      <h2>Send the combined round 1 message to every participant</h2>
      ${outBox(d.out1)}
    </section>
    <section class="card">
      <h2>Collect the round 2 messages</h2>
      ${progress(d.got2)}
      <div class="row">${importBtn('Import round 2 message', "Import a participant's round 2 message.")}${abort}</div>
    </section>`;
  }
  return `<section class="card">${steps(labels, 4)}
      <div class="note good"><b>Key generated.</b> It is safe to use once every participant has imported the certificate below and sees the same group key.</div>
      <h2>Send the certificate to every participant</h2>
      ${outBox(d.out2)}
    </section>
    ${S.group ? groupCard(S.group) : ''}
    <section class="card flat"><p class="small muted">Save the recovery data from the Backup tab and share it with the participants. It is public, and lets anyone restore the group key and each participant recover their share.</p>
      <div class="row"><button class="btn" data-act="tab" data-tab="backup">Go to Backup</button></div></section>`;
}

function viewSignParticipant() {
  const s = S.sign;
  if (!S.group) {
    return `<section class="card"><h2>No key share loaded</h2><p>Generate a key with the other participants, or restore your key share from a backup.</p>
      <div class="row"><button class="btn primary" data-act="tab" data-tab="keygen">Key generation</button>
      ${importBtn('Restore backup', 'Import a key share backup, or your host secret key followed by the recovery data.', false)}</div></section>`;
  }
  if (!s) {
    return `<section class="card"><h2>Waiting for a signing request</h2>
      <p>The coordinator sends the message to sign. You review it here before anything is signed.</p>
      <div class="row">${importBtn('Import signing request', 'Import the signing request from the coordinator.')}</div></section>`;
  }
  const labels = ['Review', 'Nonce', 'Sign'];
  const key = `<dl class="kv">${kv('Verifies under (x-only)', s.key)}${kv('Session', s.ssid.slice(0, 8), false)}</dl>`;
  if (s.stage === 'failed') {
    return `<section class="card"><h2>Signing</h2>${failure(s.error, 'p_sign_abort')}</section>`;
  }
  if (s.stage === 'review') {
    return `<section class="card">${steps(labels, 0)}
      <h2>Sign this message?</h2>
      ${messageBlock(s.msg)}${tweakList(s.tweaks)}${key}
      ${s.msg.text === null ? '<div class="note warn">These are opaque bytes. Approve only if you know what they stand for.</div>' : ''}
      <div class="row"><button class="btn primary" data-act="do" data-op="p_sign_approve">Approve and create nonce</button>
      <button class="btn quiet" data-act="do" data-op="p_sign_abort">Reject</button></div>
    </section>`;
  }
  if (s.stage === 'round1') {
    return `<section class="card">${steps(labels, 1)}
      <h2>Send your nonce to the coordinator</h2>
      ${outBox(s.out)}
    </section>
    <section class="card">
      <h2>Then import the signing package</h2>
      <p class="muted small">The coordinator sends it once enough signers have answered. Your partial signature is created when you import it.</p>
      <div class="row">${importBtn('Import signing package', 'Import the signing package from the coordinator.')}
      <button class="btn danger quiet" data-act="do" data-op="p_sign_abort">Abort</button></div>
      <div class="note warn">Keep this tab open. The secret nonce lives only in memory and is used exactly once; if the tab is closed, ask the coordinator for a new request.</div>
    </section>
    <section class="card flat"><details data-keep ${ui.msgOpen ? 'open' : ''}><summary>What you approved</summary>${messageBlock(s.msg)}${tweakList(s.tweaks)}${key}</details></section>`;
  }
  return `<section class="card">${steps(labels, 3)}
      <h2>Send your partial signature to the coordinator</h2>
      <p class="muted small">Signing set: ${s.signers.map(no).join(', ')}.</p>
      ${outBox(s.out)}
      <div class="row"><button class="btn" data-act="do" data-op="p_sign_abort">Done</button></div>
    </section>
    <section class="card flat"><details data-keep ${ui.msgOpen ? 'open' : ''}><summary>What you signed</summary>${messageBlock(s.msg)}${tweakList(s.tweaks)}${key}</details></section>`;
}

function viewSignCoordinator() {
  const s = S.sign;
  const g = S.group;
  if (!g) {
    return `<section class="card"><h2>No group key loaded</h2><p>Run a key generation, or restore the group from its recovery data.</p>
      <div class="row"><button class="btn primary" data-act="tab" data-tab="keygen">Key generation</button>
      ${importBtn('Import recovery data', 'Import the recovery data of the group.', false)}</div></section>`;
  }
  const labels = ['Message', 'Nonces', 'Partial signatures', 'Signature'];
  if (!s) {
    const d = ui.draft;
    return `<section class="card">${steps(labels, 0)}
      <h2>What should be signed?</h2>
      ${messageInput('draft')}
      <details ${d.tweaks ? 'open' : ''}><summary>Advanced: key tweaks</summary>
        <div class="field"><span class="label">One per line, applied in order: <span class="mono">plain:&lt;32-byte hex&gt;</span> (BIP32) or <span class="mono">xonly:&lt;32-byte hex&gt;</span> (Taproot)</span>
        <textarea rows="2" class="mono" data-bind="draft.tweaks" spellcheck="false" autocomplete="off" autocapitalize="off">${esc(d.tweaks)}</textarea></div>
      </details>
      <div class="row"><button class="btn primary" data-act="sign-start">Create signing request</button></div>
    </section>
    <section class="card flat"><p class="small muted">Signing with the ${g.t}-of-${g.n} group key <span class="mono">${esc(g.fp)}</span>. The result is a BIP340 Schnorr signature over the SHA-256 digest of the message.</p></section>`;
  }
  const abort = `<button class="btn danger quiet" data-act="confirm" data-op="c_sign_abort" data-ask="Abort this signing session?">Abort</button>`;
  const what = `<section class="card flat"><details data-keep ${ui.msgOpen ? 'open' : ''}><summary>Message being signed</summary>${messageBlock(s.msg)}${tweakList(s.tweaks)}
    <dl class="kv">${kv('Verifies under (x-only)', s.key)}</dl></details></section>`;
  const chips = (ids, have) => `<div class="row">${ids.map((i) => `<span class="chip ${have.includes(i) ? 'good' : ''}">${no(i)} ${have.includes(i) ? 'received' : 'waiting'}</span>`).join('')}</div>`;
  if (s.stage === 'failed') {
    return `<section class="card"><h2>Signing</h2>${failure(s.error, 'c_sign_abort')}</section>${what}`;
  }
  if (s.stage === 'round1') {
    const enough = s.nonces.length >= g.t;
    return `<section class="card">${steps(labels, 1)}
      <h2>Send the signing request to the signers</h2>
      <p class="muted small">At least ${g.t} of the ${g.n} participants have to answer.</p>
      ${outBox(s.request)}
    </section>
    <section class="card">
      <div class="head"><h2>Collect the nonces</h2><span class="chip ${enough ? 'good' : ''}">${s.nonces.length} of ${g.t} needed</span></div>
      ${s.nonces.length ? chips(s.nonces, s.nonces) : ''}
      <div class="row">${importBtn('Import nonce', "Import a signer's nonce.", !enough)}
      <button class="btn ${enough ? 'primary' : ''}" data-act="do" data-op="c_sign_package" ${enough ? '' : 'disabled'}>Build signing package</button>${abort}</div>
      <p class="muted small">Building the package fixes the signing set: every participant whose nonce is in must then deliver a partial signature.</p>
    </section>${what}`;
  }
  if (s.stage === 'round2') {
    return `<section class="card">${steps(labels, 2)}
      <h2>Send the signing package to the signers</h2>
      ${outBox(s.package)}
    </section>
    <section class="card">
      <h2>Collect the partial signatures</h2>
      ${chips(s.signers, s.partials)}
      <div class="row">${importBtn('Import partial signature', "Import a signer's partial signature.")}${abort}</div>
    </section>${what}`;
  }
  return `<section class="card">${steps(labels, 4)}
      <div class="verdict good">${ICON.ok}<span>Signature complete and verified</span></div>
      <dl class="kv">${kv('Signature (BIP340, 64 bytes)', s.signature.sig)}${kv('Public key (x-only)', s.signature.pubkey)}</dl>
      <h3>Signature with its message</h3>
      ${outBox(s.signature.out)}
      <div class="row"><button class="btn primary" data-act="do" data-op="c_sign_abort">Sign another message</button>
      <button class="btn" data-act="verify-signed">Check in Verify tab</button></div>
    </section>${what}`;
}

function viewBackup() {
  const g = S.group;
  const participant = S.role === 'participant';
  const forget = participant ? 'p_forget_share' : 'c_forget_group';
  const restore = `<section class="card">
    <h2>Restore</h2>
    <p class="muted small">${participant
      ? 'Import a key share backup, or your host secret key followed by the recovery data of the group.'
      : 'Import the recovery data of a group to coordinate signing for it.'}</p>
    <div class="row">${importBtn('Import backup', participant
      ? 'Import a key share backup, a host secret key backup or recovery data.'
      : 'Import the recovery data of the group.', !g)}</div>
  </section>`;
  if (!g) {
    return `${participant && S.host ? secretCard('host_secret', 'Host secret key',
      'Identifies this device. With the recovery data of a group it restores your key share.') : ''}${restore}`;
  }
  return `${groupCard(g, participant ? 'Your group key' : 'Group key')}
    ${participant ? secretCard('share', 'Key share backup',
      `Share ${no(g.idx)} of the group key, complete and ready to sign with. Whoever holds ${g.t} of these shares controls the key. Store it like a private key.`) : ''}
    ${participant && S.host ? secretCard('host_secret', 'Host secret key',
      'Alternative to the share backup: this key plus the recovery data below restores the same share.') : ''}
    <section class="card">
      <div class="head"><h2>Recovery data</h2><span class="chip">public</span></div>
      ${g.recovery
        ? `<p class="small muted">The signed transcript of the key generation. It holds no secrets: keep copies anywhere and give it to every participant. ${participant ? 'With your host secret key it restores your share.' : 'It restores this coordinator.'}</p>${outBox(g.recovery)}`
        : `<p class="small muted">This share was restored from a share backup, which does not include the recovery data. Import it if you have it, to keep everything together.</p>
           <div class="row">${importBtn('Import recovery data', 'Import the recovery data of the group.', false)}</div>`}
    </section>
    ${restore}
    <div class="row end"><button class="btn danger quiet" data-act="confirm" data-op="${forget}"
      data-ask="${participant ? 'Forget the key share on this device? Without a backup it is lost.' : 'Forget the group key on this device?'}">${participant ? 'Forget key share' : 'Forget group key'}</button></div>`;
}

function viewVerify() {
  const v = ui.verify;
  const r = S.verified;
  return `${r ? `<section class="card">
      <div class="verdict ${r.valid ? 'good' : 'danger'}">${r.valid ? ICON.ok : ICON.bad}<span>${r.valid ? 'Valid signature' : 'Invalid signature'}</span></div>
      ${r.valid && r.ours ? '<div class="note good">Signed by the group key loaded on this device.</div>' : ''}
      ${r.valid && !r.ours && S.group ? '<div class="note warn">The signature is valid for the public key below, which is <b>not</b> the plain group key loaded on this device.</div>' : ''}
      ${r.valid ? '' : `<div class="note">The check covers the exact bytes of the message shown below (${formatBytes(r.msg.len)}): a stray space or line break, a different notation, or another key makes it fail.</div>`}
      ${messageBlock(r.msg)}
      <dl class="kv">${kv('Public key (x-only)', r.pubkey)}${kv('Signature', r.sig)}</dl>
      <div class="row"><button class="btn" data-act="do" data-op="clear_verify">Clear</button></div>
    </section>` : ''}
    <section class="card">
      <h2>Verify a signature</h2>
      <p class="muted small">Import a signature exported by a coordinator, or enter the parts by hand.</p>
      <div class="row">${importBtn('Import signature', 'Import a signature exported by the coordinator.', !r)}</div>
    </section>
    <section class="card">
      <h2>Enter by hand</h2>
      ${messageInput('verify')}
      <div class="field"><span class="label">Public key (hex: x-only, or compressed)</span>
        <input type="text" class="mono" data-bind="verify.pubkey" value="${esc(v.pubkey)}" spellcheck="false" autocomplete="off" autocapitalize="off"></div>
      <div class="field"><span class="label">Signature (64 bytes hex)</span>
        <textarea rows="2" class="mono" data-bind="verify.sig" spellcheck="false" autocomplete="off" autocapitalize="off">${esc(v.sig)}</textarea></div>
      <div class="row"><button class="btn primary" data-act="verify">Verify</button>
      ${S.group ? '<button class="btn" data-act="verify-ours">Use group key</button>' : ''}</div>
    </section>`;
}

// ---------------------------------------------------------------- render

function tabsFor(role) {
  const tabs = [['keygen', '<span class="wide">Key generation</span><span class="narrow">Keygen</span>'], ['sign', 'Sign'], ['backup', 'Backup'], ['verify', 'Verify']];
  return role === 'participant' ? [['identity', 'Identity'], ...tabs] : tabs;
}

function render() {
  timers.forEach(clearInterval);
  timers = [];
  outs = [];
  if (qrCache.size > 64) qrCache.clear();

  const online = navigator.onLine;
  const net = `<span class="chip net ${online ? 'warn' : 'good'}" title="${online
    ? 'This device reports a network connection. The page itself cannot use it, but an offline device is safer for real keys.'
    : 'This device reports no network connection.'}"><i></i><span>${online ? 'Device online' : 'Offline'}</span></span>`;
  let body;
  let tabs = '';
  if (!S.role) {
    body = viewRoles();
  } else {
    const list = tabsFor(S.role);
    if (!list.some(([id]) => id === ui.tab)) ui.tab = list[0][0];
    tabs = `<nav class="tabs" role="tablist">${list
      .map(([id, label]) => `<button role="tab" data-act="tab" data-tab="${id}" aria-selected="${ui.tab === id}">${label}</button>`)
      .join('')}</nav>`;
    const participant = S.role === 'participant';
    const view = {
      identity: viewIdentity,
      keygen: participant ? viewKeygenParticipant : viewKeygenCoordinator,
      sign: participant ? viewSignParticipant : viewSignCoordinator,
      backup: viewBackup,
      verify: viewVerify,
    }[ui.tab];
    body = `<main>${view()}</main>`;
  }
  $('#app').innerHTML = `<header class="top">
      <div class="bar"><div class="brand">${ICON.logo}<span${S.role ? ' class="wide"' : ''}>FROST Wallet</span></div>${net}${
        S.role ? `<span class="chip accent">${S.role === 'participant' ? 'Participant' : 'Coordinator'}</span>
        <button class="btn mini" data-act="import" data-hint="Scan, paste or open any message or backup. The wallet works out what it is.">Import</button>
        <button class="btn mini" data-act="exit" aria-label="End session"><span class="wide">End session</span><span class="narrow">End</span></button>` : ''
      }</div>${tabs}
    </header>${body}
    <footer><p>Nothing leaves this page: its Content-Security-Policy blocks all network access, and nothing is written to browser storage. Unaudited software — use at your own risk.</p>
    <p class="mono">v${VERSION} · core sha256 ${WASM_SHA256.slice(0, 16)}…</p>
    <p><button class="btn mini" data-act="download-page">${ICON.down}Download this page</button> to keep a copy and open it on an offline device.</p></footer>`;
  document.querySelectorAll('.out').forEach(mountOut);
}

function mountOut(el) {
  const { out, secret } = outs[el.dataset.out];
  const mode = ui.outMode;
  const seg = (id, label) => `<button data-act="out-mode" data-mode="${id}" aria-pressed="${mode === id}">${label}</button>`;
  let body;
  if (mode === 'text') {
    body = `<textarea class="mono" rows="4" readonly spellcheck="false">${esc(out.data)}</textarea>
      <div class="row"><button class="btn" data-act="copy" data-val="${esc(out.data)}">Copy text</button><span class="muted small">${out.data.length} characters</span></div>`;
  } else if (mode === 'file') {
    body = `<div class="filebox"><span class="mono">${esc(out.name)}.txt</span><button class="btn" data-act="download">Save file</button></div>`;
  } else {
    const parts = qrParts(out.data);
    const sizes = [['low', 'Coarse'], ['mid', 'Normal'], ['high', 'Dense']]
      .map(([id, label]) => `<button data-act="density" data-density="${id}" aria-pressed="${ui.density === id}">${label}</button>`)
      .join('');
    body = `<div class="qr"></div>
      <div class="qr-ctl">${parts.length > 1
        ? `<button class="btn mini" data-act="qr-prev" aria-label="Previous part">◀</button><span class="count"></span>
           <button class="btn mini" data-act="qr-next" aria-label="Next part">▶</button><button class="btn mini" data-act="qr-pause">Pause</button>`
        : ''}<div class="seg" title="How much data goes into one QR code">${sizes}</div></div>
      ${parts.length > 1 ? `<p class="muted small" style="text-align:center">Animated sequence of ${parts.length} codes. The scanner collects them in any order.</p>` : ''}`;
    el.qr = { parts, index: 0, paused: false };
  }
  el.innerHTML = `<div class="out-head"><div class="seg">${seg('qr', 'QR code')}${seg('text', 'Text')}${seg('file', 'File')}</div>${
    secret ? '<span class="chip danger">secret — show to no one</span>' : ''
  }</div>${body}`;
  if (mode === 'qr') {
    showQr(el);
    if (el.qr.parts.length > 1) {
      timers.push(setInterval(() => {
        if (!el.qr.paused) stepQr(el, 1);
      }, 550));
    }
  }
}

function qrParts(data) {
  const cap = DENSITY[ui.density];
  if (data.length <= cap) return [data];
  const count = Math.ceil(data.length / (cap - 24));
  const size = Math.ceil(data.length / count);
  // The tail of every payload is its checksum: a stable id for the sequence.
  const id = data.slice(-6);
  return Array.from({ length: count }, (_, i) => `frostqr:${i + 1}/${count}:${id}:${data.slice(i * size, (i + 1) * size)}`);
}

function qrSvg(text) {
  let svg = qrCache.get(text);
  if (svg) return svg;
  const { width, modules } = encodeQr(text);
  const quiet = 4;
  const size = width + 2 * quiet;
  let path = '';
  for (let y = 0; y < width; y++) {
    for (let x = 0; x < width; x++) {
      if (!modules[y][x]) continue;
      let run = 1;
      while (x + run < width && modules[y][x + run]) run++;
      path += `M${x + quiet} ${y + quiet}h${run}v1h-${run}z`;
      x += run;
    }
  }
  svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
  qrCache.set(text, svg);
  return svg;
}

function showQr(el) {
  const { parts, index } = el.qr;
  $('.qr', el).innerHTML = qrSvg(parts[index]);
  const count = $('.count', el);
  if (count) count.textContent = `${index + 1} / ${parts.length}`;
}

function stepQr(el, delta) {
  const q = el.qr;
  q.index = (q.index + delta + q.parts.length) % q.parts.length;
  showQr(el);
}

function toast(text, error = false) {
  const el = document.createElement('div');
  el.className = `toast${error ? ' err' : ''}`;
  el.textContent = text;
  const box = $('#toasts');
  box.append(el);
  while (box.children.length > 3) box.firstChild.remove();
  setTimeout(() => el.remove(), error ? 7000 : 4000);
}

function forgetRevealed() {
  ui.reveal = {};
  qrCache.clear();
}

// ---------------------------------------------------------------- export helpers

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Clipboard API is unavailable on some file:// pages; fall back.
    const area = document.createElement('textarea');
    area.value = text;
    area.style.cssText = 'position:fixed;opacity:0';
    document.body.append(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    if (!ok) throw new Error('Copying is blocked here. Select the text and copy it by hand.');
  }
}

const download = (name, text) => saveFile(`${name}.txt`, `${text}\n`, 'text/plain');

function saveFile(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// ---------------------------------------------------------------- import

// Feeds one scanned, pasted or uploaded string to the wallet. Parts of a QR
// sequence are collected until the payload is whole.
function ingest(text) {
  text = text.trim();
  const part = PART.exec(text);
  if (part) {
    const [, index, total, id, chunk] = part;
    const i = Number(index);
    const n = Number(total);
    if (!n || i < 1 || i > n) throw new Error('Malformed QR sequence part.');
    // A sequence keeps cycling on the other screen after it was imported.
    if (sheet.done.has(id)) return { ignored: true };
    if (!sheet.asm || sheet.asm.id !== id || sheet.asm.n !== n) sheet.asm = { id, n, chunks: new Map() };
    sheet.asm.chunks.set(i, chunk);
    if (sheet.asm.chunks.size < n) return { partial: true, got: sheet.asm.chunks.size, n };
    text = Array.from({ length: n }, (_, k) => sheet.asm.chunks.get(k + 1)).join('');
    sheet.asm = null;
    const result = call({ op: 'import', data: text });
    sheet.done.add(id);
    return result;
  }
  const result = call({ op: 'import', data: text });
  sheet.seen.add(text);
  return result;
}

function sheetIngest(text) {
  if (sheet.seen.has(text)) return;
  let result;
  try {
    result = ingest(text);
  } catch (error) {
    render();
    sheetStatus('danger', error.message);
    return;
  }
  if (result.ignored) return;
  if (result.partial) {
    sheetStatus('', `Collected ${result.got} of ${result.n} codes…`, result.got / result.n);
    return;
  }
  ui.tab = result.tab;
  forgetRevealed();
  render();
  if (result.more) {
    sheetStatus('good', `${result.message} Ready for the next one.`);
    const area = $('#paste');
    if (area) area.value = '';
  } else {
    closeSheet();
    toast(result.message);
  }
}

function sheetStatus(kind, text, progress) {
  const el = $('#sheet-status');
  if (!el) {
    toast(text, kind === 'danger');
    return;
  }
  el.innerHTML = `<div class="note ${kind}">${esc(text)}</div>${
    progress === undefined ? '' : `<div class="progress" style="margin-top:8px"><i style="width:${Math.round(progress * 100)}%"></i></div>`
  }`;
}

function openSheet(hint) {
  sheet.open = true;
  sheet.hint = hint || '';
  sheet.seen = new Set();
  sheet.done = new Set();
  sheet.asm = null;
  drawSheet();
}

function closeSheet() {
  stopCamera();
  sheet.open = false;
  const el = $('#sheet');
  el.hidden = true;
  el.innerHTML = '';
}

function drawSheet() {
  stopCamera();
  const seg = (mode, label) => `<button data-act="sheet-mode" data-mode="${mode}" aria-pressed="${sheet.mode === mode}">${label}</button>`;
  let body;
  if (sheet.mode === 'scan') {
    body = `<div class="viewfinder idle"><video muted playsinline></video><button class="btn primary" data-act="camera">Start camera</button></div>
      <div class="row"><label class="btn grow"><input type="file" accept="image/*" capture="environment" class="hidden-input" data-file="import">Take a photo instead</label></div>
      <p class="muted small">Point the camera at the QR code. For an animated sequence, hold steady until every part is collected.</p>`;
  } else if (sheet.mode === 'file') {
    body = `<label class="drop"><input type="file" multiple class="hidden-input" data-file="import">
      <strong>Choose files</strong><span>Saved <span class="mono">.txt</span> messages, or photos and screenshots of QR codes. You can also drop files anywhere on the page.</span></label>`;
  } else {
    body = `<textarea id="paste" class="mono" rows="5" placeholder="Paste the text here. It starts with FRST…" spellcheck="false" autocomplete="off" autocapitalize="off" autocorrect="off"></textarea>
      <div class="row"><button class="btn primary grow" data-act="paste-import">Import</button>${
        navigator.clipboard?.readText ? '<button class="btn" data-act="paste-clip">Paste from clipboard</button>' : ''
      }</div>`;
  }
  const el = $('#sheet');
  el.hidden = false;
  el.innerHTML = `<div class="sheet" role="dialog" aria-modal="true" aria-label="Import">
    <div class="head"><h2>Import</h2><button class="btn mini" data-act="sheet-close">Close</button></div>
    ${sheet.hint ? `<p class="muted small">${esc(sheet.hint)}</p>` : ''}
    <div class="seg">${seg('scan', 'Scan QR')}${seg('paste', 'Paste text')}${seg('file', 'Open file')}</div>
    <div id="sheet-status"></div>
    ${body}
  </div>`;
  if (sheet.mode === 'paste') $('#paste').focus();
}

async function startCamera() {
  const finder = $('.viewfinder');
  const video = $('video', finder);
  try {
    if (!navigator.mediaDevices?.getUserMedia) throw new Error('not supported on this page');
    cam.stream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
    });
  } catch (error) {
    sheetStatus('warn', `The camera is not available (${error.name === 'Error' ? error.message : error.name}). Take a photo of the code instead, or use text or a file.`);
    return;
  }
  if (!finder.isConnected) return stopCamera();
  $('button', finder)?.remove();
  finder.classList.remove('idle');
  video.srcObject = cam.stream;
  await video.play().catch(() => {});
  cam.last = '';
  cam.timer = setInterval(() => scanFrame(video), 140);
}

function stopCamera() {
  clearInterval(cam.timer);
  cam.timer = 0;
  cam.stream?.getTracks().forEach((track) => track.stop());
  cam.stream = null;
}

function scanFrame(video) {
  if (!video.isConnected) return stopCamera();
  if (video.readyState < 2 || !video.videoWidth) return;
  for (const text of scanSource(video, video.videoWidth, video.videoHeight, 960)) {
    // The same code stays in view for many frames; an error for it is
    // reported once, then again only after a pause.
    const now = Date.now();
    if (text === cam.last && now - cam.lastAt < 4000) continue;
    cam.last = text;
    cam.lastAt = now;
    sheetIngest(text);
    if (!sheet.open) return;
  }
}

// Draws an image source scaled to fit `limit` pixels and looks for QR codes.
// Small pictures (a cropped screenshot, say) may be enlarged up to `zoom`
// times: the detector needs a few pixels per module.
function scanSource(source, width, height, limit, zoom = 1) {
  const k = Math.min(zoom, limit / Math.max(width, height));
  const w = Math.max(1, Math.round(width * k));
  const h = Math.max(1, Math.round(height * k));
  cam.canvas.width = w;
  cam.canvas.height = h;
  const ctx = cam.canvas.getContext('2d', { willReadFrequently: true });
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, w, h);
  ctx.drawImage(source, 0, 0, w, h);
  return decodeQr(ctx.getImageData(0, 0, w, h).data, w, h);
}

function loadImage(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error(`${file.name} is not a readable image.`));
    };
    img.src = url;
  });
}

function isImage(bytes, type) {
  if (type.startsWith('image/')) return true;
  const head = toHex(bytes.subarray(0, 4));
  return head === '89504e47' || head.startsWith('ffd8ff') || head === '47494638' || head === '52494646';
}

// A file may be a saved text message, a raw binary blob or a picture of a QR code.
async function readPayloads(file) {
  if (file.size > 40 * 1048576) throw new Error(`${file.name} is too large.`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (isImage(bytes, file.type)) {
    const img = await loadImage(file);
    for (const limit of [1600, 1000, 640, 2400]) {
      const found = scanSource(img, img.naturalWidth, img.naturalHeight, limit, 4);
      if (found.length) return found;
    }
    throw new Error(`No QR code found in ${file.name}. Try a sharper, closer photo.`);
  }
  if (MAGIC.every((b, i) => bytes[i] === b)) return [toBase64(bytes)];
  if (bytes.length > 4 * 1048576) throw new Error(`${file.name} is not a FROST wallet message.`);
  return [dec.decode(bytes)];
}

async function importFiles(files) {
  for (const file of files) {
    try {
      for (const text of await readPayloads(file)) {
        sheetIngest(text);
      }
    } catch (error) {
      sheetStatus('danger', error.message);
    }
  }
}

// ---------------------------------------------------------------- actions

function run(req) {
  call(req);
  render();
}

function parseTweaks(text) {
  return text.split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const m = /^(plain|xonly)\s*:\s*([0-9a-f]{64})$/i.exec(line);
    if (!m) throw new Error(`Cannot read tweak "${line}". Expected plain:<64 hex digits> or xonly:<64 hex digits>.`);
    return { value: m[2].toLowerCase(), xonly: m[1].toLowerCase() === 'xonly' };
  });
}

function decodeBase64(text) {
  const clean = text.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (!clean || /[^A-Za-z0-9+/]/.test(clean) || clean.length % 4 === 1) throw new Error('The message is not valid base64.');
  return fromBase64(clean);
}

function messageBytes(draft) {
  const { value } = draft;
  if (draft.mode === 'text') {
    if (!value) throw new Error('Enter the message first.');
    return enc.encode(value);
  }
  if (!value.trim()) throw new Error('Enter the message first.');
  return draft.mode === 'hex' ? fromHex(value, 'The message') : decodeBase64(value);
}

const actions = {
  role: (el) => {
    ui.tab = null;
    run({ op: 'set_role', role: el.dataset.role });
  },
  exit: () => {
    if (!confirm('End this session? Everything in this tab is wiped. Make sure your backups are saved.')) return;
    forgetRevealed();
    ui.draft = newDraft();
    ui.verify = { ...newDraft(), pubkey: '', sig: '' };
    run({ op: 'reset' });
  },
  tab: (el) => {
    ui.tab = el.dataset.tab;
    forgetRevealed();
    render();
    scrollTo(0, 0);
  },
  do: (el) => {
    const req = { op: el.dataset.op };
    if (el.dataset.index !== undefined) req.index = Number(el.dataset.index);
    if (/forget/.test(req.op)) forgetRevealed();
    run(req);
  },
  confirm: (el) => {
    if (confirm(el.dataset.ask)) actions.do(el);
  },
  import: (el) => openSheet(el.dataset.hint),
  'dkg-start': () => {
    const input = $('[data-bind="t"]');
    run({ op: 'c_dkg_start', t: Number(input?.value) });
    ui.t = null;
  },
  // Switching notation rewrites the entered bytes in the new one. If that
  // cannot be done the switch is refused, so the field never shows something
  // other than what will be signed.
  'msg-mode': (el) => {
    const d = ui[el.dataset.group];
    const to = el.dataset.mode;
    if (d.value) {
      const bytes = messageBytes(d);
      if (to === 'text') {
        try {
          d.value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch {
          throw new Error('These bytes are not readable text. Keep them as hex or base64, or clear the field first.');
        }
      } else d.value = to === 'hex' ? toHex(bytes) : toBase64(bytes);
    }
    d.mode = to;
    render();
  },
  'msg-view': (el) => {
    ui.msgView = el.dataset.mode;
    render();
  },
  'sign-start': () => {
    const draft = ui.draft;
    const bytes = messageBytes(draft);
    if (bytes.length > 65536) throw new Error('The message is too large: at most 64 KiB can be passed around.');
    run({ op: 'c_sign_start', msg: toHex(bytes), tweaks: parseTweaks(draft.tweaks) });
    ui.draft = { ...newDraft(), mode: draft.mode };
  },
  // Carries the finished signature over to the Verify tab and checks it there.
  'verify-signed': () => {
    const { msg, signature } = S.sign;
    ui.verify = msg.text === null
      ? { ...newDraft(), mode: 'hex', value: msg.hex, pubkey: signature.pubkey, sig: signature.sig }
      : { ...newDraft(), value: msg.text, pubkey: signature.pubkey, sig: signature.sig };
    ui.tab = 'verify';
    actions.verify();
  },
  'verify-ours': () => {
    ui.verify.pubkey = S.group.xonly;
    render();
  },
  verify: () => {
    const v = ui.verify;
    run({ op: 'verify', pubkey: v.pubkey.trim(), sig: v.sig.replace(/\s+/g, ''), msg: toHex(messageBytes(v)) });
    scrollTo(0, 0);
  },
  reveal: (el) => {
    ui.reveal[el.dataset.what] = call({ op: 'export', what: el.dataset.what });
    render();
  },
  hide: (el) => {
    delete ui.reveal[el.dataset.what];
    qrCache.clear();
    render();
  },
  copy: async (el) => {
    await copyText(el.dataset.val);
    toast('Copied.');
  },
  download: (el) => {
    const { out } = outs[el.closest('.out').dataset.out];
    download(out.name, out.data);
  },
  'download-page': () => saveFile('frost-wallet.html', PAGE_SOURCE, 'text/html'),
  'out-mode': (el) => {
    ui.outMode = el.dataset.mode;
    render();
  },
  density: (el) => {
    ui.density = el.dataset.density;
    render();
  },
  'qr-prev': (el) => stepQr(el.closest('.out'), -1),
  'qr-next': (el) => stepQr(el.closest('.out'), 1),
  'qr-pause': (el) => {
    const q = el.closest('.out').qr;
    q.paused = !q.paused;
    el.textContent = q.paused ? 'Play' : 'Pause';
  },
  'sheet-close': closeSheet,
  'sheet-mode': (el) => {
    sheet.mode = el.dataset.mode;
    drawSheet();
  },
  camera: startCamera,
  'paste-import': () => {
    const text = $('#paste').value;
    if (!text.trim()) return sheetStatus('danger', 'Nothing to import yet: paste the text first.');
    sheet.seen.delete(text.trim());
    sheetIngest(text.trim());
  },
  'paste-clip': async () => {
    try {
      $('#paste').value = await navigator.clipboard.readText();
    } catch {
      sheetStatus('warn', 'The browser did not allow reading the clipboard. Paste by hand instead.');
    }
  },
};

document.addEventListener('click', async (event) => {
  if (event.target.id === 'sheet') return closeSheet();
  const el = event.target.closest('[data-act]');
  if (!el || el.disabled) return;
  try {
    await actions[el.dataset.act](el);
  } catch (error) {
    render();
    toast(error.message, true);
  }
});

// Drafts are kept outside the DOM so that a re-render does not lose them.
function bind(event) {
  const key = event.target.dataset?.bind;
  if (!key) return;
  const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
  if (key === 't') ui.t = Number(value) || null;
  else {
    const [group, field] = key.split('.');
    ui[group][field] = value;
  }
}
document.addEventListener('input', bind);

document.addEventListener('change', async (event) => {
  const input = event.target;
  if (!input.dataset?.file || !input.files.length) return;
  const files = [...input.files];
  input.value = '';
  importFiles(files);
});

// A re-render must not fold the message details the reader has opened.
document.addEventListener('toggle', (event) => {
  if (event.target.matches?.('details[data-keep]')) ui.msgOpen = event.target.open;
}, true);

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && sheet.open) closeSheet();
});

window.addEventListener('dragover', (event) => event.preventDefault());
window.addEventListener('drop', (event) => {
  event.preventDefault();
  const files = [...(event.dataTransfer?.files || [])];
  if (!files.length || !S.role) return;
  if (!sheet.open) {
    sheet.mode = 'file';
    openSheet('');
  }
  importFiles(files);
});

for (const type of ['online', 'offline']) {
  window.addEventListener(type, () => {
    // Re-rendering would restart a running camera view only if the sheet were
    // part of the app root; it is not, so this is safe at any time.
    if (wasm) render();
  });
}

window.addEventListener('beforeunload', (event) => {
  if (S.role && (S.host || S.group || S.dkg || S.sign || S.roster?.length)) {
    event.preventDefault();
    event.returnValue = '';
  }
});

boot().catch((error) => {
  $('#app').innerHTML = `<p class="fatal">The wallet core failed to start: ${esc(error.message)}. This browser may not support WebAssembly.</p>`;
});
