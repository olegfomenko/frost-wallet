//! Core of the offline FROST wallet.
//!
//! [`wallet::Wallet`] holds one session and is driven by JSON requests;
//! [`wire`] defines the blobs that cross the air gap; [`qr`] draws and reads
//! QR codes. On `wasm32` the crate exposes a small C ABI (see [`ffi`]) that
//! the page calls directly: no bindings generator and no JavaScript
//! dependencies are involved.

pub mod qr;
pub mod wallet;
pub mod wire;

#[cfg(target_arch = "wasm32")]
mod ffi;
