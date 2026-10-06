//! The WebAssembly boundary.
//!
//! Buffers are passed as `(pointer, length)` into the module's linear memory.
//! The page allocates with [`fw_alloc`], writes its input, calls a function
//! and reads the result, which is returned packed as `pointer << 32 | length`
//! and must be released with [`fw_free`]. Input buffers are wiped and freed
//! by the callee.

use crate::wallet::Wallet;
use std::cell::RefCell;
use zeroize::Zeroize;

#[link(wasm_import_module = "env")]
unsafe extern "C" {
    /// Fills the buffer from the browser's CSPRNG (`crypto.getRandomValues`).
    fn fw_random(ptr: *mut u8, len: usize);
}

thread_local! {
    static WALLET: RefCell<Wallet> = RefCell::new(Wallet::new(Box::new(|buf: &mut [u8]| {
        // SAFETY: the pointer and length describe a live, writable buffer.
        unsafe { fw_random(buf.as_mut_ptr(), buf.len()) }
    })));
}

#[unsafe(no_mangle)]
pub extern "C" fn fw_alloc(len: usize) -> *mut u8 {
    let mut buf = vec![0u8; len].into_boxed_slice();
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` and `len` must come from [`fw_alloc`] or from a returned result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fw_free(ptr: *mut u8, len: usize) {
    drop(unsafe { take(ptr, len) });
}

/// Handles one JSON request (see [`Wallet::handle`]).
///
/// # Safety
/// `ptr` and `len` must describe a buffer obtained from [`fw_alloc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fw_call(ptr: *mut u8, len: usize) -> u64 {
    let request = unsafe { take(ptr, len) };
    let response = match std::str::from_utf8(&request.0) {
        Ok(request) => WALLET.with(|wallet| wallet.borrow_mut().handle(request)),
        Err(_) => r#"{"ok":false,"error":"Malformed request."}"#.to_string(),
    };
    give(response.into_bytes())
}

/// Decodes the QR codes in an RGBA image; returns a JSON array of strings.
///
/// # Safety
/// `ptr` must describe a buffer of `4 * width * height` bytes obtained from
/// [`fw_alloc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fw_qr_decode(ptr: *mut u8, width: usize, height: usize) -> u64 {
    let Some(len) = width.checked_mul(height).and_then(|px| px.checked_mul(4)) else {
        return give(b"[]".to_vec());
    };
    let image = unsafe { take(ptr, len) };
    let found = crate::qr::decode_rgba(&image.0, width, height);
    give(serde_json::Value::from(found).to_string().into_bytes())
}

/// An input buffer taken back from the page; wiped when dropped, since
/// requests may carry secret backups.
struct Input(Box<[u8]>);

impl Drop for Input {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

unsafe fn take(ptr: *mut u8, len: usize) -> Input {
    // SAFETY: per the callers' contracts the buffer was leaked by `fw_alloc`
    // or `give` as a boxed slice of exactly `len` bytes.
    Input(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) })
}

fn give(bytes: Vec<u8>) -> u64 {
    let mut buf = bytes.into_boxed_slice();
    let (ptr, len) = (buf.as_mut_ptr() as u64, buf.len() as u64);
    std::mem::forget(buf);
    ptr << 32 | len
}
