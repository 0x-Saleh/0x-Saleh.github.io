(() => {
  const get = (id) => document.getElementById(id);
  const panel = get('encoder');
  const controls = panel.querySelector('.encoder-controls');
  const input = get('encoding-input');
  const output = get('encoding-output');
  const copy = get('encoding-copy');
  const reuse = get('encoding-reuse');
  const error = get('encoding-error');
  const status = get('encoding-status');
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  let result = '';

  function convert(text, format, encode) {
    if (format === 'URL') {
      return encode ? encodeURIComponent(text) : decodeURIComponent(text);
    }
    if (encode) {
      const bytes = encoder.encode(text);
      if (format === 'Hex') {
        return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
      }
      let binary = '';
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary);
    }
    const compact = text.replace(/[\t\n\f\r ]/g, '');
    if (format === 'Base64') {
      return decoder.decode(Uint8Array.from(atob(compact), (char) => char.charCodeAt(0)));
    }
    if (/[^0-9a-f]/i.test(compact) || compact.length % 2) throw new Error('Invalid hex');
    const bytes = new Uint8Array(compact.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Number.parseInt(compact.slice(i * 2, i * 2 + 2), 16);
    }
    return decoder.decode(bytes);
  }

  function update() {
    const format = controls.querySelector('[name="encoding-format"]:checked').value;
    const encode = controls.querySelector('[name="encoding-action"]:checked').value === 'encode';
    let message = '';
    result = '';
    try {
      if (input.value) result = convert(input.value, format, encode);
    } catch {
      message = 'Could not encode input';
      if (!encode) message = format === 'URL' ? 'Invalid URL encoding' : `Invalid ${format}`;
    }
    output.value = result;
    copy.disabled = !result;
    reuse.disabled = !result;
    if (error.textContent !== message) error.textContent = message;
    input.setAttribute('aria-invalid', String(Boolean(message)));
    status.textContent = '';
  }

  input.addEventListener('input', update);
  controls.addEventListener('change', update);
  get('encoding-clear').addEventListener('click', () => {
    input.value = '';
    update();
    input.focus();
  });
  reuse.addEventListener('click', () => {
    input.value = result;
    update();
    input.focus();
  });
  copy.addEventListener('click', async () => {
    const text = result;
    try {
      await navigator.clipboard.writeText(text);
      if (result === text) status.textContent = 'Copied';
    } catch {
      if (result !== text) return;
      output.focus();
      output.select();
      status.textContent = 'Output selected for manual copy';
    }
  });
  update();
  panel.hidden = false;
})();
