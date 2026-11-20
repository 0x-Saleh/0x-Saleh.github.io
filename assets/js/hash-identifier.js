(() => {
  const maxLength = 4096;
  const digestTypes = new Map([
    [16, ['MySQL pre-4.1']],
    [32, ['MD5', 'NTLM', 'MD4']],
    [40, ['SHA-1']],
    [56, ['SHA-224', 'SHA3-224']],
    [64, ['SHA-256', 'SHA3-256']],
    [96, ['SHA-384', 'SHA3-384']],
    [128, ['SHA-512', 'SHA3-512']]
  ]);
  const base64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  // Return decoded byte length only for canonical Base64, with the required padding convention.
  function base64Length(value, unpadded = false) {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return 0;
    const data = value.replace(/=+$/, '');
    const remainder = data.length % 4;
    const padding = value.length - data.length;
    if (remainder === 1 || padding !== (unpadded ? 0 : (4 - remainder) % 4)) return 0;
    const last = base64.indexOf(data.at(-1));
    if ((remainder === 2 && last % 16) || (remainder === 3 && last % 4)) return 0;
    return Math.floor(data.length * 6 / 8);
  }

  const positiveInteger = (text) => /^[1-9][0-9]*$/.test(text) && Number.isSafeInteger(Number(text));

  // Reference encoding: github.com/P-H-C/phc-winner-argon2/blob/master/src/encoding.c
  function argonType(hash) {
    const match = /^\$argon2(id|i|d)\$(?:v=(?:16|19)\$)?m=([1-9][0-9]*),t=([1-9][0-9]*),p=([1-9][0-9]*)\$([^$]+)\$([^$]+)$/.exec(hash);
    if (!match) return '';
    const [, variant, memory, time, lanes, salt, tag] = match;
    if (![memory, time, lanes].every(positiveInteger) || Number(lanes) > 0xffffff ||
        Number(memory) < 8 * Number(lanes) || Number(memory) > 0xffffffff ||
        Number(time) > 0xffffffff || base64Length(salt, true) < 8 || base64Length(tag, true) < 4) return '';
    return 'Argon2' + variant;
  }

  function scryptParameters(n, r, p) {
    if (![n, r, p].every(positiveInteger) || Number(n) <= 1 || Number(r) * Number(p) >= 2 ** 30) return false;
    const cost = BigInt(n);
    return (cost & (cost - 1n)) === 0n && Math.log2(Number(n)) < 16 * Number(r);
  }

  // Django's dollar-separated and Werkzeug's method-prefixed encodings.
  function kdfType(hash) {
    const parts = hash.split('$');
    const [method, first, second, third, fourth, fifth] = parts;
    if (parts.length === 4 && /^pbkdf2_sha(?:1|256)$/.test(method) &&
        positiveInteger(first) && /^[^\s$]+$/.test(second)) {
      const sha = method === 'pbkdf2_sha1' ? '1' : '256';
      if (base64Length(third) === (sha === '1' ? 20 : 32)) return `PBKDF2-HMAC-SHA${sha} (Django)`;
    }
    if (parts.length === 6 && method === 'scrypt' && /^[^\s$]+$/.test(second) &&
        scryptParameters(first, third, fourth) && base64Length(fifth) === 64) return 'scrypt (Django)';
    if (parts.length !== 3 || !/^[A-Za-z0-9]+$/.test(first) || !/^[0-9a-f]+$/.test(second)) return '';
    const [algorithm, option, param, parallel, extra] = method.split(':');
    if (algorithm === 'scrypt' && extra === undefined && param && parallel &&
        second.length === 128 && scryptParameters(option, param, parallel)) return 'scrypt (Werkzeug)';
    if (algorithm === 'pbkdf2' && positiveInteger(param ?? '') && parallel === undefined) {
      const lengths = { sha1: 40, sha256: 64, sha512: 128 };
      if (second.length === lengths[option]) return `PBKDF2-HMAC-${option.toUpperCase()} (Werkzeug)`;
    }
    return '';
  }

  function structuredType(hash) {
    // crypt(5): modular crypt identifiers, settings, salts and fixed-size outputs.
    if (/^\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{21}[.Oeu][./A-Za-z0-9]{30}[.CGKOSWaeimquy26]$/.test(hash)) return 'bcrypt';
    if (/^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$/.test(hash)) return 'MD5-crypt';
    const crypt = /^\$([56])\$(?:rounds=[1-9][0-9]{3,8}\$)?([!-~]{1,16})\$([./A-Za-z0-9]+)$/.exec(hash);
    if (crypt && !/[$:;*!\\]/.test(crypt[2]) && crypt[3].length === (crypt[1] === '5' ? 43 : 86)) {
      return crypt[1] === '5' ? 'SHA-256-crypt' : 'SHA-512-crypt';
    }
    // phpass / WordPress: 8 salt characters and 22 digest characters with a bounded cost.
    if (/^\$[PH]\$[5-9A-S][./A-Za-z0-9]{29}[./01]$/.test(hash)) return 'phpass';
    if (/^\*[0-9A-Fa-f]{40}$/.test(hash)) return 'MySQL 4.1 (mysql_native_password)';

    const ldap = /^\{(SHA|SSHA|MD5|SMD5)\}(.+)$/i.exec(hash);
    if (ldap) {
      const scheme = ldap[1].toUpperCase();
      const bytes = base64Length(ldap[2]);
      const digestLength = scheme.endsWith('SHA') ? 20 : 16;
      const salted = scheme === 'SSHA' || scheme === 'SMD5';
      if (salted ? bytes > digestLength : bytes === digestLength) {
        return `LDAP {${scheme}}`;
      }
    }
    return argonType(hash) || kdfType(hash);
  }

  function identify(input) {
    const hash = input.trim();
    if (!hash) return { kind: 'empty', types: [] };
    if (hash.length > maxLength) return { kind: 'too-long', types: [] };
    const type = structuredType(hash);
    if (type) return { kind: 'strong', types: [type] };
    const candidates = digestTypes.get(hash.length);
    if (candidates && /^[0-9A-Fa-f]+$/.test(hash)) {
      // MySQL's old representation encodes two 31-bit values.
      if (hash.length === 16 && !/^[0-7][0-9A-Fa-f]{7}[0-7]/.test(hash)) return { kind: 'unknown', types: [] };
      return { kind: 'possible', types: [...candidates], length: hash.length };
    }
    return { kind: 'unknown', types: [] };
  }

  if (typeof module === 'object' && module.exports) {
    module.exports = { identify };
    return;
  }

  const input = document.getElementById('hash-input');
  const clear = document.getElementById('hash-clear');
  const title = document.getElementById('hash-result-title');
  const types = document.getElementById('hash-result-types');
  const note = document.getElementById('hash-result-note');
  const titles = { strong: 'Strong Format Match', possible: 'Possible Matches', unknown: 'Unknown' };

  function update() {
    const result = identify(input.value);
    const heading = titles[result.kind] ?? '';
    const candidates = result.types.join(' · ');
    const notes = {
      empty: 'Paste a hash to see its possible types.',
      strong: 'The format matches a documented structure.',
      possible: `${result.length} hexadecimal characters. Length alone cannot identify the algorithm.`,
      unknown: 'Unknown hash format.',
      'too-long': 'Input is too long. Paste a single hash.'
    };
    // Avoid repeating identical announcements on each keystroke.
    if (title.textContent !== heading) title.textContent = heading;
    if (types.textContent !== candidates) types.textContent = candidates;
    if (note.textContent !== notes[result.kind]) note.textContent = notes[result.kind];
    title.hidden = !heading;
    types.hidden = !candidates;
    clear.disabled = !input.value;
  }

  input.addEventListener('input', update);
  clear.addEventListener('click', () => {
    input.value = '';
    input.focus();
    update();
  });
  update();
  document.getElementById('hash-tool').hidden = false;
})();
