// The bridge to the WebAssembly core.
//
// Buffers cross as (pointer, length) into the module's memory; a result
// comes back packed as `pointer << 32 | length` and is wiped and freed here
// once copied out. Randomness is the only thing the core asks of its host.

const enc = new TextEncoder();
const dec = new TextDecoder();

// Starts the core from its bytes and returns a function that sends it one
// JSON request and returns the response: `{ ok, result | error, state }`.
export async function loadCore(wasmBytes) {
  let wasm = null;
  const { instance } = await WebAssembly.instantiate(wasmBytes, {
    env: {
      fw_random(ptr, len) {
        crypto.getRandomValues(new Uint8Array(wasm.memory.buffer, ptr, len));
      },
    },
  });
  wasm = instance.exports;

  return (request) => {
    const bytes = enc.encode(JSON.stringify(request));
    const ptr = wasm.fw_alloc(bytes.length);
    new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);
    bytes.fill(0);
    const packed = wasm.fw_call(ptr, bytes.length);
    const at = Number(packed >> 32n);
    const len = Number(packed & 0xffffffffn);
    const view = new Uint8Array(wasm.memory.buffer, at, len);
    const response = JSON.parse(dec.decode(view));
    view.fill(0);
    wasm.fw_free(at, len);
    return response;
  };
}
