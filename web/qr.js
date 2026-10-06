// QR codes: drawing with uqr, reading with jsQR. Kept free of the DOM so
// that it can be tested under Node.

import jsQR from 'jsqr';
import { encode } from 'uqr';

// The symbol for `text` as rows of modules; `true` is dark. No quiet zone.
export function encodeQr(text) {
  // The codes are shown on a screen or printed by the user, never damaged in
  // transit, so the lowest correction level keeps them as coarse (and as easy
  // to scan) as possible.
  const { size, data } = encode(text, { ecc: 'L', boostEcc: false, border: 0 });
  return { width: size, modules: data };
}

// The texts of the QR codes found in an RGBA image: one at most.
export function decodeQr(rgba, width, height) {
  // The wallet's own codes are always dark on light.
  const found = jsQR(rgba, width, height, { inversionAttempts: 'dontInvert' });
  return found?.data ? [found.data] : [];
}
