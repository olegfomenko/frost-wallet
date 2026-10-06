# FROST Wallet

An offline threshold wallet in one HTML file. It generates a FROST threshold key with
[ChillDKG](https://github.com/olegfomenko/chilldkg), backs it up, and produces BIP340 Schnorr
signatures over arbitrary data. There is no server and no networking: every protocol message
is carried between devices by hand, as a QR code, a text string or a file.

⚠️ Neither this wallet nor the `chilldkg-rs` library underneath has been audited. Use at your
own risk.

## Build

```bash
cargo xtask build
```

This compiles `core/` to WebAssembly and inlines it, with the stylesheet and script from
`web/`, into `dist/frost-wallet.html`. That file is the whole application: copy it to any
device and open it in a browser. The only build dependency is the Rust toolchain pinned in
`rust-toolchain.toml` (it installs the `wasm32-unknown-unknown` target on first use); there
are no JavaScript dependencies and no bundler.

```bash
cargo test    # runs full keygen, signing and backup sessions through the core's JSON API
```

`dist/frost-wallet.html` is committed, so the page can be downloaded straight from the
repository; rebuild it before committing source changes. CI never uses that copy:
`.github/workflows/build.yml` deletes it and rebuilds the page from the sources on every
commit, with no build cache, runs the tests, and attaches the result to the run as an
artifact. Commits to the default branch are also published to GitHub Pages (enable it once
under *Settings → Pages → Source: GitHub Actions*), together with `SHA256SUMS.txt`.

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

Because of the extra hash, a signature made here is not a signature over the message bytes
themselves. In particular the wallet cannot sign a precomputed digest such as a Bitcoin
Taproot sighash as is.

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

- `core/` — the wallet, in Rust: `wallet.rs` (session model behind a JSON API), `wire.rs`
  (blobs), `qr.rs` (QR encode and decode), `ffi.rs` (the WebAssembly boundary).
- `web/` — the page: `index.html`, `app.css`, `app.js`. A thin view over the core.
- `xtask/` — the build step that produces the single file.

## Security notes

- The page's Content-Security-Policy has no `connect-src` and allows exactly one script, by
  hash, so the page cannot make network requests. Run it on an offline device anyway.
- Secrets stay in WebAssembly memory and are wiped when dropped. They reach the page only when
  you reveal a backup; the browser gives no way to wipe those copies.
- Randomness comes from the browser's `crypto.getRandomValues`.
- Signing nonces live only in memory and are used once. If a tab is closed mid-session, start
  a new session.
- Backups are not encrypted. Protect key share and host secret key backups like private keys.
