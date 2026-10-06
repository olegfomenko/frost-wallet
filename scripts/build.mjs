// `npm run build`: compiles the wallet core to WebAssembly, bundles the page
// script, and inlines both, with the stylesheet, into the single
// self-contained dist/frost-wallet.html.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const TARGET = 'wasm32-unknown-unknown';
const OUTPUT = 'dist/frost-wallet.html';

const sha256 = (data) => createHash('sha256').update(data);
const run = (command, args) => execFileSync(command, args, { cwd: root, encoding: 'utf8' });

// Compiler flags that replace machine-specific source paths, which end up in
// the module's panic messages, with fixed ones, so that a published page
// does not carry the builder's home directory.
function remapFlags() {
  const sysroot = run('rustc', ['--print', 'sysroot']).trim();
  const commit = /^commit-hash: (.+)$/m.exec(run('rustc', ['-vV']))?.[1];
  if (!commit) throw new Error('cannot determine the rustc commit');
  const cargoHome = process.env.CARGO_HOME || join(homedir(), '.cargo');
  // When several rules match a path the compiler applies the last one, so
  // they go from the outermost directory to the most specific. Cargo hands
  // the compiler its home as spelled in the environment, which need not be
  // the canonical name, so both are covered. The standard library is
  // referred to as /rustc/<commit> unless its sources are installed locally;
  // the local copy is mapped to the same name.
  return [
    `${root}=/frost-wallet`,
    `${realpathSync(cargoHome)}=/cargo`,
    `${cargoHome}=/cargo`,
    `${sysroot}=/rust`,
    `${sysroot}/lib/rustlib/src/rust=/rustc/${commit}`,
  ].map((rule) => `--remap-path-prefix=${rule}`).join(' ');
}

execFileSync(
  'cargo',
  ['build', '--release', '--locked', '--target', TARGET, '--package', 'frost-wallet-core'],
  { cwd: root, stdio: 'inherit', env: { ...process.env, RUSTFLAGS: remapFlags() } },
);
const wasm = readFileSync(join(root, 'target', TARGET, 'release', 'frost_wallet_core.wasm'));

// The script is bundled but not minified: what runs in the page stays
// readable. esbuild escapes any closing script tag inside the bundle.
const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const script = buildSync({
  entryPoints: [join(root, 'web/app.js')],
  bundle: true,
  write: false,
  format: 'iife',
  platform: 'browser',
  target: 'es2022',
  charset: 'utf8',
  legalComments: 'inline',
  define: {
    __VERSION__: JSON.stringify(version),
    __WASM_SHA256__: JSON.stringify(sha256(wasm).digest('hex')),
  },
}).outputFiles[0].text;
if (/<\/script/i.test(script)) throw new Error('the bundled script contains a closing script tag');

// Function replacements, so that `$` in the inlined text is taken literally.
const read = (name) => readFileSync(join(root, 'web', name), 'utf8');
const html = read('index.html')
  // The page's Content-Security-Policy allows exactly this script.
  .replace('@@SCRIPT_SHA256@@', () => sha256(script).digest('base64'))
  .replace('/*@@CSS@@*/', () => read('app.css'))
  .replace('@@WASM@@', () => wasm.toString('base64'))
  .replace('/*@@JS@@*/', () => script);
if (/@@[A-Z_0-9]+@@/.test(html)) throw new Error('web/index.html has an unfilled placeholder');

mkdirSync(join(root, 'dist'), { recursive: true });
writeFileSync(join(root, OUTPUT), html);
console.log(
  `${OUTPUT}: ${Math.round(Buffer.byteLength(html) / 1024)} KiB (wasm ${Math.round(wasm.length / 1024)} KiB)\n` +
    `sha256 ${sha256(html).digest('hex')}`,
);
