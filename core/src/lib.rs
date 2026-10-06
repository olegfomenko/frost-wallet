//! Core of the offline FROST wallet.
//!
//! [`wallet::Wallet`] holds one session and is driven by JSON requests;
//! [`wire`] defines the blobs that cross the air gap. On `wasm32` the crate
//! exposes a small C ABI (see [`ffi`]) that the page calls directly, without
//! a bindings generator. Everything else the page does, QR codes included,
//! is JavaScript.

pub mod wallet;
pub mod wire;

#[cfg(target_arch = "wasm32")]
mod ffi;
