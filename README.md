# FROST Wallet

An offline threshold wallet in one HTML file. It generates a FROST threshold key with
[ChillDKG](https://github.com/olegfomenko/chilldkg), backs it up, and signs with it: arbitrary
messages, and Bitcoin transactions (PSBTs) spending from the key's Taproot addresses. There is
no server and no networking: every protocol message is carried between devices by hand, as a
QR code, a text string or a file.

⚠️ Neither this wallet nor the `chilldkg-rs` library underneath has been audited. Use at your
own risk.

## Build

```bash
npm ci
npm run build
```

This compiles `core/` to WebAssembly, bundles the script from `web/`, and inlines both, with
the stylesheet, into `dist/frost-wallet.html`. That file is the whole application: copy it to
any device and open it in a browser.

You need Node 20 or later and the Rust toolchain pinned in `rust-toolchain.toml` (it installs
the `wasm32-unknown-unknown` target on first use). The page's runtime JavaScript
dependencies are [uqr](https://github.com/unjs/uqr) and [jsQR](https://github.com/cozmo/jsQR)
for drawing and reading QR codes, and, for Bitcoin,
[@scure/btc-signer](https://github.com/paulmillr/scure-btc-signer) with the
[noble](https://paulmillr.com/noble/) curve and hash libraries it builds on.
[esbuild](https://esbuild.github.io) bundles the script, unminified. All are pinned to exact
versions.

```bash
npm test
```

`dist/` is not committed. `.github/workflows/build.yml` builds the page from the sources on
every commit, with no build cache, runs the tests and attaches `frost-wallet.html` to the run
as an artifact. Commits to the default branch are also published to GitHub Pages (enable it
once under *Settings → Pages → Source: GitHub Actions*), together with `SHA256SUMS.txt`.

The page has a **Download** button in its header. It saves an exact copy of the
page as it was served, to carry to an offline device.

## Using it

Every device opens the same file and picks a role.

- **Participant** holds one share of the key. It has a long-term *host key*, takes part in key
  generation, reviews and co-signs messages, and keeps its own backups.
- **Coordinator** holds no secrets. It collects the participants' messages, sends the combined
  ones back and assembles the final signature. It can be a separate device or a second tab.

Anything received goes through one **Import** sheet (scan a QR code, paste text, or open a
file or a photo of a QR code). The wallet recognises what it was given and routes it; a
message for the wrong role or the wrong session is refused with an explanation.

### Key generation

| Step | Participant | Coordinator |
|---|---|---|
| 1 | Create a host key, send the **host public key** | Import every host public key, set the threshold, start |
| 2 | Import the **parameters**, compare fingerprints, join; send the **round 1 message** | Send the parameters; collect round 1 messages |
| 3 | Import the **combined round 1 message**; send the **round 2 message** | Send the combined message; collect round 2 messages |
| 4 | Import the **certificate** — the key share is ready | Send the certificate |

### Signing

| Step | Participant | Coordinator |
|---|---|---|
| 1 | | Enter the raw message as text, hex or base64, send the **signing request** |
| 2 | Review the message, approve; send the **nonce** | Collect at least `t` nonces, build the **signing package** |
| 3 | Import the package; send the **partial signature** | Collect the partial signatures — the **signature** is assembled and verified |

Messages always travel raw, so every signer sees what it approves, in text, hex or base64. What
is signed is always the **SHA-256 digest** of the message: the result is a plain BIP340
signature over that 32-byte digest, under the group's x-only key (or under a tweaked key, if
BIP32/Taproot tweaks were given). The **Verify** tab takes the raw message the same way and
hashes it before checking.

Because of the extra hash, a signature over a message is not a signature over the message
bytes themselves, and a message session cannot be used to sign a precomputed digest. Bitcoin
transactions are signed through their own kind of session, below.

### Bitcoin

The **Bitcoin** tab turns the group key into a wallet:

- an **extended public key** and an output **descriptor**, `tr(xpub/<0;1>/*)`, each with a QR
  code, to import into Sparrow, Bitcoin Core or another wallet as watch-only;
- the Taproot **addresses** below it, with QR codes: `m/0/*` for receiving, `m/1/*` for change.

Addresses are BIP 32 children of the group key, spent by key path only (as in BIP 86). A
threshold key has no chain code of its own, so the xpub uses the fixed one that BIP 328
defines for aggregate keys.

To spend, build the transaction in the watch-only wallet and bring its PSBT to the
coordinator's **Sign** tab, as a QR code (the UR format wallets show, single or animated), a
`.psbt` file, or base64 or hex text. The coordinator sees what it pays, hands the same PSBT
on to the signers, and has its inputs signed **one at a time**, each in an ordinary signing
session as in the table above. When every input is signed, the signed PSBT and the raw
transaction are ready, to take back to the watch-only wallet as a QR code, text or file.

The core knows nothing about Bitcoin and is not changed for it. It signs the SHA-256 of a
message; the signature hash of a Taproot input is the SHA-256 of a message too (BIP 341's
tagged hash), so the page gives the core exactly that message, with the tweaks that lead from
the group key to the key of the coin. All Bitcoin code is JavaScript, in `web/bitcoin.js`.

A signing request therefore carries that message, which does not say what the transaction
pays. So once a signer has imported such a request, an **Add the transaction** button lets
them give the page the transaction itself (as text, a QR code or a file). This is optional.
The transaction is accepted only if it is the one the request belongs to, matched by signature
hash and key, and the request is then shown as "input 2 of this transaction" with the
outputs, change and fee. Approving without it is signing blind. A participant cannot enter a
transaction anywhere else, or before a request.

What it does not do: script-path spends, signature types other than the default (all of the
transaction), hardened derivation, and reading PSBTs in the BBQr QR format.

### Backups

Nothing is stored by the page. Closing the tab wipes the session, so export what you need:

| Backup | Secret | Restores |
|---|---|---|
| Key share | **yes** | A participant, ready to sign |
| Host secret key | **yes** | A participant, together with the recovery data |
| Recovery data | no | A coordinator; and each participant's share, given their host secret key |

## Message format

Every payload is one binary blob, shown as base64 text that always starts with `FRST`:

```
magic (3) | version (1) | kind (1) | body | checksum (4, SHA-256 prefix)
```

The same string is the QR content, the clipboard text and the file content. A payload too big
for one comfortable QR code is shown as an animated sequence of
`frostqr:<i>/<n>:<id>:<chunk>` codes, which the scanner collects in any order. See
`core/src/wire.rs` for the body layouts; the recovery data body is byte-compatible with the
ChillDKG reference (`transcript || cert`).

## Layout

- `core/` — the part in Rust: `wallet.rs` (the session flow, behind a JSON API), `wire.rs`
  (encoding of the blobs), `ffi.rs` (the WebAssembly boundary). It holds every secret and
  decides what reaches the ChillDKG and FROST drivers.
- `web/` — the page: `index.html`, `app.css`, `app.js` (the interface and all input and
  output), `core.js` (the bridge to the WebAssembly core), `qr.js` (QR codes), `bitcoin.js`
  (xpub, addresses, reading and completing PSBTs), `ur.js` (the QR format for PSBTs).
- `scripts/build.mjs` — the build step that produces the single file.
- `test/` — JavaScript tests; the Rust ones are in `core/tests/`.

## Security notes

- The page's Content-Security-Policy has no `connect-src` and allows exactly one script, by
  hash, so the page cannot make network requests. Run it on an offline device anyway.
- Secrets stay in WebAssembly memory and are wiped when dropped. They reach the page only when
  you reveal a backup; the browser gives no way to wipe those copies.
- Randomness comes from the browser's `crypto.getRandomValues`. When creating a host key you
  can add your own: a drawing, dice rolls and coin flips. Their hash is XORed with the
  device's random bytes, so they can only make the key harder to guess. Device randomness
  can also be turned off; the key is then the hash of your input alone, and the dice and
  coins must add up to at least 128 bits (50 rolls, 128 flips, or a mix). A drawing is mixed
  in but not counted, because it cannot be measured.
- Signing nonces live only in memory and are used once. If a tab is closed mid-session, start
  a new session.
- Backups are not encrypted. Protect key share and host secret key backups like private keys.
