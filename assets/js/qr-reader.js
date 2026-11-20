(() => {
  const workerURL = new URL('qr-reader-worker.js', document.currentScript.src);
  const reader = document.querySelector('#qr-reader');
  const drop = document.querySelector('#qr-drop');
  const fileInput = document.querySelector('#qr-file');
  const preview = document.querySelector('#qr-preview');
  const icon = document.querySelector('#qr-icon');
  const output = document.querySelector('#qr-output');
  const status = document.querySelector('#qr-status');
  const copy = document.querySelector('#qr-copy');
  let active;
  let detector;

  function report(text, error = false) {
    status.textContent = text;
    status.toggleAttribute('data-error', error);
  }

  async function supportsImage(file) {
    const bytes = new Uint8Array(await file.slice(0, 12).arrayBuffer());
    const start = String.fromCharCode(...bytes);
    return start.startsWith('\x89PNG\r\n\x1a\n') || start.startsWith('\xff\xd8\xff') ||
      (start.startsWith('RIFF') && start.slice(8) === 'WEBP');
  }

  async function getDetector() {
    try {
      const formats = await globalThis.BarcodeDetector?.getSupportedFormats();
      if (formats?.includes('qr_code')) {
        return new BarcodeDetector({ formats: ['qr_code'] });
      }
    } catch {
      // Some browsers expose the API without a working platform detector.
    }
    return null;
  }

  function decodePixels(imageData, signal) {
    return new Promise((resolve, reject) => {
      signal.throwIfAborted();
      const worker = new Worker(workerURL);
      function finish(callback, value) {
        worker.terminate();
        signal.removeEventListener('abort', abort);
        callback(value);
      }
      function abort() { finish(reject, signal.reason); }
      signal.addEventListener('abort', abort, { once: true });
      worker.onmessage = (event) => finish(resolve, event.data);
      worker.onerror = (event) => {
        event.preventDefault();
        finish(reject, new Error('QR decoder unavailable'));
      };
      const { data: pixels, width, height } = imageData;
      try {
        worker.postMessage({ pixels, width, height }, [pixels.buffer]);
      } catch (error) {
        finish(reject, error);
      }
    });
  }

  async function decode(image, signal) {
    detector ??= getDetector();
    const native = await detector;
    signal.throwIfAborted();
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d', { willReadFrequently: true });
    const width = image.naturalWidth;
    const height = image.naturalHeight;
    const longest = Math.max(width, height);
    const detailed = Math.min(1, 4096 / longest, Math.sqrt(12_000_000 / (width * height)));
    const quick = Math.min(detailed, 1600 / longest);

    try {
      for (const scale of new Set([quick, detailed])) {
        signal.throwIfAborted();
        canvas.width = Math.max(1, Math.round(width * scale));
        canvas.height = Math.max(1, Math.round(height * scale));
        context.fillStyle = '#fff';
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.drawImage(image, 0, 0, canvas.width, canvas.height);
        if (native) {
          let codes;
          try {
            codes = await native.detect(canvas);
          } catch {
            // Continue with jsQR if native decoding fails for this image.
          }
          signal.throwIfAborted();
          if (codes?.length) {
            codes.sort((a, b) => a.boundingBox.y - b.boundingBox.y || a.boundingBox.x - b.boundingBox.x);
            return codes[0].rawValue;
          }
        }
        const result = await decodePixels(context.getImageData(0, 0, canvas.width, canvas.height), signal);
        if (result !== null) return result;
      }
      return null;
    } finally {
      canvas.width = canvas.height = 0;
    }
  }

  async function read(file) {
    active?.abort();
    active = new AbortController();
    const { signal } = active;
    output.textContent = '';
    copy.disabled = true;
    preview.replaceChildren();
    preview.hidden = true;
    icon.hidden = false;
    report('Reading image…');
    if (file.size > 24 * 1024 * 1024) {
      report('Image is too large.', true);
      return;
    }
    try {
      const supported = await supportsImage(file);
      signal.throwIfAborted();
      if (!supported) {
        report('Unsupported image. Use PNG, JPEG, or WebP.', true);
        return;
      }
      const image = new Image();
      image.alt = 'Selected image preview';
      const url = URL.createObjectURL(file);
      try {
        image.src = url;
        await image.decode();
      } finally {
        URL.revokeObjectURL(url);
      }
      signal.throwIfAborted();
      if (image.naturalWidth * image.naturalHeight > 24_000_000) {
        report('Image is too large.', true);
        return;
      }
      preview.replaceChildren(image);
      preview.hidden = false;
      icon.hidden = true;
      const result = await decode(image, signal);
      signal.throwIfAborted();
      if (result === null) {
        report('No QR code found.', true);
        return;
      }
      output.textContent = result;
      copy.disabled = result.length === 0;
      report(result.length ? 'QR code decoded.' : 'QR code contains no text.');
    } catch {
      if (!signal.aborted) report('Image could not be read.', true);
    }
  }

  document.addEventListener('paste', (event) => {
    const file = Array.from(event.clipboardData?.items ?? [])
      .find((item) => item.kind === 'file' && item.type.startsWith('image/'))?.getAsFile();
    if (!file) return;
    event.preventDefault();
    void read(file);
  });
  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    fileInput.value = '';
    if (file) void read(file);
  });
  drop.addEventListener('dragover', (event) => {
    if (!event.dataTransfer.types.includes('Files')) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
    drop.setAttribute('data-dragging', '');
  });
  drop.addEventListener('dragleave', (event) => {
    if (!drop.contains(event.relatedTarget)) drop.removeAttribute('data-dragging');
  });
  drop.addEventListener('drop', (event) => {
    event.preventDefault();
    drop.removeAttribute('data-dragging');
    const file = event.dataTransfer.files[0];
    if (file) void read(file);
  });
  copy.addEventListener('click', async () => {
    const request = active;
    const text = output.textContent;
    try {
      await navigator.clipboard.writeText(text);
      if (active === request) report('Copied');
    } catch {
      if (active !== request) return;
      output.focus();
      const range = document.createRange();
      range.selectNodeContents(output);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      report('Result selected for manual copy.');
    }
  });
  reader.hidden = false;
})();
