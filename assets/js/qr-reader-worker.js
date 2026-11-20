/* global jsQR */
importScripts('./vendor/jsqr/jsQR.js');

self.onmessage = ({ data: { pixels, width, height } }) => {
  const result = jsQR(pixels, width, height, { inversionAttempts: 'attemptBoth' });
  self.postMessage(result ? result.data : null);
};
