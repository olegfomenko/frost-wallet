//! `cargo xtask build`: compiles the wallet core to WebAssembly and inlines
//! it, together with the page's stylesheet and script, into the single
//! self-contained `dist/frost-wallet.html`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::{env, fs};

const TARGET: &str = "wasm32-unknown-unknown";
const WASM: &str = "frost_wallet_core.wasm";
const OUTPUT: &str = "dist/frost-wallet.html";

fn main() -> ExitCode {
    let result = match env::args().nth(1).as_deref() {
        Some("build") => build(),
        _ => Err("usage: cargo xtask build".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn build() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("cannot locate the workspace root")?
        .to_path_buf();

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(&root)
        .env("RUSTFLAGS", remap_flags(&root)?)
        .args(["build", "--release", "--locked", "--target", TARGET])
        .args(["--package", "frost-wallet-core"])
        .status()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    if !status.success() {
        return Err("the WebAssembly build failed".into());
    }

    let wasm = read(&root.join("target").join(TARGET).join("release").join(WASM))?;
    let read_text = |name: &str| -> Result<String, String> {
        String::from_utf8(read(&root.join("web").join(name))?)
            .map_err(|_| format!("web/{name} is not valid UTF-8"))
    };

    let script = read_text("app.js")?
        .replace("@@VERSION@@", env!("CARGO_PKG_VERSION"))
        .replace("@@WASM_SHA256@@", &hex(&Sha256::digest(&wasm)));
    if script.contains("</script") {
        return Err("web/app.js must not contain a closing script tag".into());
    }
    // The page's Content-Security-Policy allows exactly this script.
    let script_hash = STANDARD.encode(Sha256::digest(script.as_bytes()));

    let html = read_text("index.html")?
        .replace("@@SCRIPT_SHA256@@", &script_hash)
        .replace("/*@@CSS@@*/", &read_text("app.css")?)
        .replace("@@WASM@@", &STANDARD.encode(&wasm))
        .replace("/*@@JS@@*/", &script);

    let output = root.join(OUTPUT);
    fs::create_dir_all(output.parent().ok_or("invalid output path")?)
        .and_then(|()| fs::write(&output, &html))
        .map_err(|e| format!("cannot write {}: {e}", output.display()))?;

    println!(
        "{OUTPUT}: {} KiB (wasm {} KiB)\nsha256 {}",
        html.len() / 1024,
        wasm.len() / 1024,
        hex(&Sha256::digest(html.as_bytes()))
    );
    Ok(())
}

/// Compiler flags that replace machine-specific source paths, which end up
/// in the module's panic messages, with fixed ones, so that a published page
/// does not carry the builder's home directory.
fn remap_flags(root: &Path) -> Result<String, String> {
    let rustc = |args: &[&str]| -> Result<String, String> {
        let output = Command::new(env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
            .current_dir(root)
            .args(args)
            .output()
            .map_err(|e| format!("cannot run rustc: {e}"))?;
        String::from_utf8(output.stdout).map_err(|_| "unexpected rustc output".to_string())
    };
    let sysroot = rustc(&["--print", "sysroot"])?.trim().to_string();
    let version = rustc(&["-vV"])?;
    let commit = version
        .lines()
        .find_map(|line| line.strip_prefix("commit-hash: "))
        .ok_or("cannot determine the rustc commit")?;
    let cargo_home = env::var("CARGO_HOME")
        .or_else(|_| env::var("HOME").map(|home| format!("{home}/.cargo")))
        .map_err(|_| "cannot locate the cargo home directory")?;
    // Cargo hands the compiler the directory as it was spelled in the
    // environment, which need not be its canonical name; cover both.
    let cargo_home_resolved =
        fs::canonicalize(&cargo_home).map_err(|e| format!("cannot resolve {cargo_home}: {e}"))?;

    // When several rules match a path the compiler applies the last one, so
    // they go from the outermost directory to the most specific. The standard
    // library is referred to as /rustc/<commit> unless its sources are
    // installed locally; the local copy is mapped to the same name.
    Ok([
        format!("{}=/frost-wallet", root.display()),
        format!("{}=/cargo", cargo_home_resolved.display()),
        format!("{cargo_home}=/cargo"),
        format!("{sysroot}=/rust"),
        format!("{sysroot}/lib/rustlib/src/rust=/rustc/{commit}"),
    ]
    .map(|rule| format!("--remap-path-prefix={rule}"))
    .join(" "))
}

fn read(path: &PathBuf) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
