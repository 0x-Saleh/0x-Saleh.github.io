/* FFUF v2 flags: https://github.com/ffuf/ffuf/wiki/CLI-flags
   Pure command logic first; the browser adapter below owns all DOM interaction. */
(function () {
  'use strict';
  const WORDLIST_VERSION = 3;
  // Maintained locally. Check upstream filenames before editing; increment version.
  const WORDLISTS = [
    { id: 'common', label: 'Common', path: '/usr/share/seclists/Discovery/Web-Content/common.txt' },
    { id: 'medium', label: 'Medium', path: '/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt' },
    { id: 'raft', label: 'RAFT Medium', path: '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt' },
    { id: 'big', label: 'Big', path: '/usr/share/seclists/Discovery/Web-Content/big.txt' },
    { id: 'parameters', label: 'Parameters', path: '/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt' },
    { id: 'rockyou', label: 'RockYou', path: '$HOME/wordlists/rockyou.txt' },
    { id: 'top-usernames', label: 'Top Usernames', path: '/usr/share/seclists/Usernames/top-usernames-shortlist.txt' },
    { id: 'common-names', label: 'Common Names', path: '/usr/share/seclists/Usernames/Names/names.txt' },
    { id: 'large-usernames', label: 'Large Usernames', path: '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt' }
  ];
  const ROCKYOU_EXTRACT = 'mkdir -p "$HOME/wordlists" && gzip -dc /usr/share/wordlists/rockyou.txt.gz > "$HOME/wordlists/rockyou.txt" && test -s "$HOME/wordlists/rockyou.txt" && echo "Wordlist ready"';
  const rockYouSelected = state => state.pwnbox === true && state.wordlistPreset === 'rockyou';
  const VALUE_FLAGS = {
    mc: 'mc', ms: 'ms', mw: 'mw', ml: 'ml', mr: 'mr', mt: 'mt',
    fc: 'fc', fs: 'fs', fw: 'fw', fl: 'fl', fr: 'fr', ft: 'ft',
    mmode: 'mmode', fmode: 'fmode', threads: 't', rate: 'rate',
    timeout: 'timeout', delay: 'p', extensions: 'e', output: 'o',
    format: 'of', proxy: 'x', replayProxy: 'replay-proxy'
  };
  const BOOLEAN_FLAGS = { calibration: 'ac', perHost: 'ach', ignoreComments: 'ic', quiet: 's', verbose: 'v' };
  function defaults() {
    const state = { scanType: 'directories', url: 'https://example.com/FUZZ', wordlist: 'common.txt',
      method: '', body: '', cookies: '', headers: [], requestFile: 'req.txt', protocol: 'https', rawContent: '',
      redirects: false, recursion: false, depth: '', strategy: '' };
    for (const key of Object.keys(VALUE_FLAGS)) state[key] = '';
    for (const key of Object.keys(BOOLEAN_FLAGS)) state[key] = false;
    return state;
  }
  function quote(value) {
    return "'" + String(value).replace(/'/g, "'\"'\"'") + "'";
  }
  function numberList(value, status = false, allowAll = false) {
    if (allowAll && value === 'all') return true;
    if (!/^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/.test(value)) return false;
    return value.split(',').every(part => {
      const bounds = part.split('-').map(Number);
      return bounds.every(n => Number.isSafeInteger(n) && n >= (status ? 100 : 0) && n <= (status ? 599 : Number.MAX_SAFE_INTEGER)) &&
        (bounds.length === 1 || bounds[0] <= bounds[1]);
    });
  }
  // Syntax screening only, never run a user regex against text in the browser.
  // Translate Go-only constructs for the JS syntax parser, not for execution.
  function regexError(pattern) {
    if (/\(\?(?:[=!]|<[=!])/.test(pattern) || /\\[1-9](?![0-7]{2})/.test(pattern)) {
      return 'Go regex does not support lookaround or backreferences.';
    }
    if (/\{(\d+)(?:,(\d*))?\}/g.test(pattern)) {
      for (const match of pattern.matchAll(/(?<!\\)\{(\d+)(?:,(\d*))?\}/g)) {
        if (Number(match[1]) > 1000 || Number(match[2]) > 1000) return 'Go regex repetition counts cannot exceed 1000.';
      }
    }
    const syntax = pattern.replace(/\\Q([\s\S]*?)(?:\\E|$)/g, (_, text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .replace(/\(\?[imsU-]+\)/g, '').replace(/\(\?[imsU-]+:/g, '(?:')
      .replace(/\(\?P<([A-Za-z_][\w]*)>/g, '(?<$1>')
      .replace(/\\[pP]\{[^}]+\}/g, 'x').replace(/\\[pP][A-Za-z]/g, 'x')
      .replace(/\[:\^?[a-z]+:\]/g, 'a-z').replace(/\\[Az]/g, '').replace(/\\x\{[0-9a-fA-F]+\}/g, 'x');
    try { new RegExp(syntax); } catch { return 'Check the regular expression: brackets, groups, escapes or repetition are incomplete.'; }
    return '';
  }
  function rawRequestCheck(content) {
    const lines = content.replace(/\r\n/g, '\n').split('\n');
    const first = /^(\S+) (\S+) HTTP\/1\.[01]$/.exec(lines[0]);
    if (!first) return 'Start the pasted request with METHOD /path HTTP/1.1.';
    const end = lines.indexOf('');
    if (end < 1) return 'Separate the HTTP headers and body with an empty line.';
    const headers = lines.slice(1, end);
    if (!headers.some(h => /^Host:\s*\S+/i.test(h))) return 'Include a Host header in the pasted request.';
    if (headers.some(h => !/^[!#$%&'*+.^_`|~\w-]+:[^\r\n]*$/.test(h))) return 'Use Name: Value for each pasted HTTP header.';
    const target = first[2].split('#')[0];
    const effective = [first[1], target, ...headers, lines.slice(end + 1).join('\n')].join('\n');
    if (!effective.includes('FUZZ')) return 'Place FUZZ in the request target, method, header or body, not the HTTP version or URL fragment.';
    return '';
  }
  function buildCommand(input) {
    const state = { ...defaults(), ...input };
    const errors = [], warnings = [], args = ['ffuf'];
    const flagPositions = new Set();
    const error = (field, message) => errors.push({ field, message });
    const add = (flag, value) => { flagPositions.add(args.length); args.push('-' + flag); if (value !== undefined) args.push(String(value)); };
    const raw = state.scanType === 'raw';
    const headers = (state.headers || []).filter(h => h !== '');
    const effectiveKeys = ['wordlist', ...Object.keys(VALUE_FLAGS), 'depth', 'strategy',
      ...(raw ? ['requestFile', 'protocol', 'rawContent'] : ['url', 'method', 'body', 'cookies'])];
    for (const key of effectiveKeys) {
      if (typeof state[key] !== 'string') { error(key, 'Enter a text value.'); continue; }
      if (/\x00/.test(state[key])) error(key, 'Remove the NUL character; shells cannot pass it as an argument.');
      if (!['body', 'rawContent'].includes(key) && /[\r\n]/.test(state[key])) error(key, 'Use a single line for this field.');
    }
    if (!state.wordlist.trim()) error('wordlist', 'Enter a local wordlist path.');
    if (state.wordlist.includes(':') && !state.wordlist.endsWith(':FUZZ')) error('wordlist', 'Use a plain path or the :FUZZ keyword suffix; this generator uses one FUZZ wordlist.');
    if (state.wordlist.startsWith('~')) warnings.push('Quoted paths do not expand ~. Use an absolute path to your home directory.');
    if (raw) {
      if (!state.requestFile.trim()) error('requestFile', 'Enter the raw request file path.');
      if (!['http', 'https'].includes(state.protocol)) error('protocol', 'Choose HTTP or HTTPS.');
      add('request', state.requestFile);
      if (state.protocol !== 'https') add('request-proto', state.protocol);
      if (state.rawContent.trim()) {
        const issue = rawRequestCheck(state.rawContent);
        if (issue) error('rawContent', issue);
        else warnings.push('Ensure your request file matches this preview.');
      } else warnings.push('FUZZ could not be verified. Check your request file.');
    } else {
      let parsed;
      try { parsed = new URL(state.url); } catch { /* Explained below. */ }
      if (!state.url.trim()) error('url', 'Enter a target URL.');
      else if (!parsed || !['http:', 'https:'].includes(parsed.protocol) || /\s/.test(state.url)) error('url', 'Use a valid HTTP or HTTPS URL without unencoded spaces.');
      if (parsed && parsed.hash) warnings.push('URL fragments are not sent to the server and cannot carry effective FUZZ input.');
      if (state.method && !/^[!#$%&'*+.^_`|~\w-]+$/.test(state.method)) error('method', 'Use a valid HTTP method token, such as GET or POST.');
      headers.forEach((header, index) => {
        if (!/^[!#$%&'*+.^_`|~\w-]+:[^\r\n\x00]*$/.test(header)) error('headers-list', `Header ${index + 1}: use Name: Value on a single line.`);
      });
      if (state.url.trim() && ![state.url.split('#')[0], state.method, state.cookies, state.body, ...headers].some(v => v.includes('FUZZ'))) error('url', 'Add FUZZ to the request.');
      add('u', state.url);
      if (state.method) add('X', state.method);
      for (const header of headers) add('H', header);
      if (state.cookies) add('b', state.cookies);
      if (state.body) add('d', state.body);
      if (state.body && (!state.method || state.method === 'GET')) warnings.push('The body will be sent with GET. Select POST if that is what your endpoint expects.');

    }
    if (state.redirects) add('r');
    add('w', state.wordlist);
    for (const key of ['mc', 'ms', 'mw', 'ml', 'fc', 'fs', 'fw', 'fl']) {
      if (state[key] && !numberList(state[key], key.endsWith('c'), key === 'mc')) error(key, `-${key}: use comma-separated numbers or ascending ranges${key === 'mc' ? ', or all' : ''}.`);
    }
    for (const key of ['mt', 'ft']) if (state[key] && !/^[<>]\d+$/.test(state[key])) error(key, `-${key}: use >500 or <100, in milliseconds.`);
    for (const key of ['mr', 'fr']) if (state[key]) { const issue = regexError(state[key]); if (issue) error(key, `-${key}: ${issue}`); }
    for (const key of ['threads', 'rate', 'timeout', ...(state.recursion ? ['depth'] : [])]) {
      const minimum = ['threads', 'timeout'].includes(key) ? 1 : 0;
      if (state[key] && (!/^\d+$/.test(state[key]) || !Number.isSafeInteger(Number(state[key])) || Number(state[key]) < minimum)) error(key, `Enter a whole number of ${minimum} or greater.`);
    }
    if (state.delay) {
      const parts = state.delay.split('-').map(Number);
      if (!/^\d+(?:\.\d+)?(?:-\d+(?:\.\d+)?)?$/.test(state.delay) || parts.some(n => !Number.isFinite(n)) || (parts.length === 2 && parts[0] > parts[1])) error('delay', 'Use a nonnegative delay or ascending range, such as 0.1-2.0.');
    }
    for (const key of ['mmode', 'fmode']) if (state[key] && !['and', 'or'].includes(state[key])) error(key, 'Choose and or or.');
    if (state.format && !state.output.trim()) error('output', 'Enter an output filename.');
    if (state.format && !['json', 'ejson', 'html', 'md', 'csv', 'ecsv', 'all'].includes(state.format)) error('format', 'Choose a documented output format.');
    if (state.perHost && !state.calibration) error('perHost', 'Enable Auto Calibration to use per-host calibration.');
    if (state.quiet && state.verbose) warnings.push('Quiet and verbose are both enabled: less extra output, but detailed result lines.');
    if (state.extensions && state.extensions.split(',').some(v => !v || /\s/.test(v))) error('extensions', 'Separate extensions with commas, without spaces or empty items.');
    if (state.recursion) {
      let url;
      try { url = new URL(state.url); } catch { /* URL error already shown. */ }
      if (raw || state.scanType !== 'directories' || !url || !state.url.endsWith('FUZZ') || !url.pathname.endsWith('FUZZ') || url.search || url.hash) error('recursion', 'Recursion needs a directory URL ending in FUZZ, without a query or fragment.');
      if (state.strategy && !['default', 'greedy'].includes(state.strategy)) error('strategy', 'Choose default or greedy recursion.');
      add('recursion');
      if (state.depth) add('recursion-depth', state.depth);
      if (state.strategy) add('recursion-strategy', state.strategy);
      if (state.redirects && !raw && state.strategy !== 'greedy') warnings.push('Following redirects may hide directory redirects used by default recursion.');
    } else if (state.depth || state.strategy) warnings.push('Recursion depth and strategy are kept but excluded while recursion is off.');
    for (const key of ['proxy', 'replayProxy']) {
      if (!state[key]) continue;
      try { const url = new URL(state[key]); if (!['http:', 'https:', 'socks5:'].includes(url.protocol)) throw new Error(); }
      catch { error(key, 'Use a valid HTTP, HTTPS or SOCKS5 proxy URL.'); }
    }
    if (state.mc && state.mc === state.fc) warnings.push('The status matcher and filter are identical; matching responses may all be hidden.');
    if (state.fr || state.mr) warnings.push('Regex checks cover common errors only. FFUF uses Go/RE2 syntax.');
    for (const [key, flag] of Object.entries(VALUE_FLAGS)) if (state[key] !== '') add(flag, state[key]);
    for (const [key, flag] of Object.entries(BOOLEAN_FLAGS)) if (state[key]) add(flag);
    const wordlistPosition = Array.from(flagPositions).find(i => args[i] === '-w') + 1;
    const trustedRockYou = rockYouSelected(state) && state.wordlist === '$HOME/wordlists/rockyou.txt';
    const command = errors.length ? '' : args.map((arg, i) => i === 0 || flagPositions.has(i) ? arg : (trustedRockYou && i === wordlistPosition ? '"$HOME/wordlists/rockyou.txt"' : quote(arg))).join(' ');
    // Only fixed flag tokens bypass quoting; every user value is one shell argument.
    return { command, args, errors, warnings };
  }
  function profileChanges(name, pwnbox) {
    const common = WORDLISTS[0].path;
    const medium = WORDLISTS[1].path;
    const params = WORDLISTS[4].path;
    const path = value => pwnbox ? value : value.slice(value.lastIndexOf('/') + 1);
    const changes = { scanType: 'directories', url: 'https://example.com/FUZZ', method: '', headers: [], body: '', cookies: '',
      requestFile: 'req.txt', protocol: 'https', rawContent: '', redirects: false, recursion: false, depth: '', strategy: '',
      wordlist: path(common), calibration: false, perHost: false };
    if (name === 'deep') changes.wordlist = path(medium);
    if (name === 'noise') changes.calibration = true;
    if (name === 'param-names') Object.assign(changes, { scanType: 'query', url: 'https://example.com/?FUZZ=test', wordlist: path(params) });
    if (name === 'param-values') Object.assign(changes, { scanType: 'query', url: 'https://example.com/?id=FUZZ', wordlist: 'values.txt' });
    if (name === 'vhost') Object.assign(changes, { scanType: 'vhost', url: 'https://example.com/', headers: ['Host: FUZZ.example.com'] });
    if (name === 'raw') changes.scanType = 'raw';
    return changes;
  }
  // Manual edits last until the next form-driven generation or explicit reset.
  function createCommandEditor() {
    let generated = '', manual = null;
    return {
      get value() { return manual === null ? generated : manual; },
      get edited() { return manual !== null; },
      get canCopy() { return this.value.trim().length > 0; },
      generate(value) { generated = value; manual = null; },
      edit(value) { manual = value; },
      reset() { manual = null; }
    };
  }
  async function copyCommand(command, clipboard) {
    if (!command || !clipboard || typeof clipboard.writeText !== 'function') return false;
    try { await clipboard.writeText(command); return true; } catch { return false; }
  }
  const api = { buildCommand, quote, defaults, numberList, regexError, rawRequestCheck, profileChanges, copyCommand, createCommandEditor, WORDLISTS, WORDLIST_VERSION, ROCKYOU_EXTRACT, rockYouSelected };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof document === 'undefined') return;

  const form = document.getElementById('ffuf-form');
  if (!form) return;
  const get = id => document.getElementById(id);
  const view = () => form.querySelector('[name="view"]:checked').value;
  let selectedProfile = 'quick', undo = null, result;
  const editor = createCommandEditor();
  const fieldKeys = Object.keys(defaults()).filter(key => key !== 'headers');
  let headerIndex = 0;
  function addHeader(value = '') {
    const row = document.createElement('div'); row.className = 'header-row';
    const input = document.createElement('input'); input.type = 'text'; input.value = value;
    input.name = 'header'; input.id = 'header-' + (++headerIndex); input.autocomplete = 'off'; input.spellcheck = false;
    input.setAttribute('aria-label', 'HTTP header ' + headerIndex); input.setAttribute('aria-describedby', 'headers-help');
    input.placeholder = 'Name: Value';
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'text-button'; remove.textContent = 'Remove';
    remove.setAttribute('aria-label', 'Remove HTTP header ' + headerIndex);
    remove.addEventListener('click', () => { row.remove(); get('add-header').focus(); markCustom(); render(); });
    row.append(input, remove); get('headers-list').append(row);
    return input;
  }
  function readState() {
    const state = {};
    for (const key of fieldKeys) { const control = get(key); state[key] = control.type === 'checkbox' ? control.checked : control.value; }
    state.pwnbox = get('pwnbox').checked; state.wordlistPreset = get('wordlistPreset').value;
    state.headers = Array.from(get('headers-list').querySelectorAll('input'), input => input.value);
    return state;
  }
  function writeState(state) {
    for (const key of fieldKeys) { const control = get(key); if (control.type === 'checkbox') control.checked = state[key]; else control.value = state[key]; }
    get('headers-list').replaceChildren(); state.headers.forEach(value => addHeader(value));
  }
  function markCustom() { selectedProfile = 'custom'; }
  function showField(field) {
    const control = get(field);
    if (!control) return;
    form.querySelector('[name="view"][value="advanced"]').checked = true;
    updateVisibility(readState());
    const details = control.closest('details'); if (details) details.open = true;
    if (field === 'headers-list') (control.querySelector('input') || get('add-header')).focus();
    else control.focus();
  }
  function updateVisibility(state) {
    const raw = state.scanType === 'raw';
    const advanced = view() === 'advanced';
    const speedParent = get(advanced ? 'advanced-speed' : 'speed-options');
    if (get('speed-fields').parentElement !== speedParent) speedParent.append(get('speed-fields'));
    get('speed-options').hidden = advanced;
    get('raw-fields').hidden = !raw; get('url-fields').hidden = raw;
    get('rockyou-warning').hidden = !rockYouSelected(state);
    get('copy-extraction').textContent = 'Copy';
    get('pwnbox-options').hidden = !get('pwnbox').checked;
    form.querySelectorAll('.advanced-only').forEach(el => { el.hidden = !advanced; });
    const requestNeeded = ['headers', 'vhost', 'form'].includes(state.scanType);
    get('manual-request-fields').hidden = raw;
    get('request-options').hidden = !(advanced || (!raw && requestNeeded));
    if (!advanced && requestNeeded) get('request-options').open = true;
  }
  function render() {
    const state = readState(); updateVisibility(state); result = buildCommand(state);
    editor.generate(result.command);
    updateEditor();
    get('profile-status').textContent = selectedProfile === 'custom' ? 'Custom' : '';
    form.querySelectorAll('[data-profile]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.profile === selectedProfile)));
    const active = [];
    if (state.threads) active.push(state.threads + ' threads');
    if (state.rate) active.push(state.rate === '0' ? 'no rate cap' : state.rate + ' requests/s');
    if (state.calibration) active.push('auto calibration');
    if (state.recursion) active.push('recursion');
    const extra = Object.keys(VALUE_FLAGS).filter(k => !['threads','rate'].includes(k) && state[k]).map(k => '-' + VALUE_FLAGS[k]);
    active.push(...extra);
    for (const [key, flag] of Object.entries(BOOLEAN_FLAGS)) if (key !== 'calibration' && state[key]) active.push('-' + flag);
    get('active-summary').textContent = active.join(' | ');
    get('active-summary').hidden = editor.edited || view() === 'advanced' || active.length === 0;
    form.querySelectorAll('[aria-invalid]').forEach(el => el.removeAttribute('aria-invalid'));
    get('validation').replaceChildren();
    get('validation').hidden = editor.edited;
    const list = document.createElement('ul');
    for (const issue of result.errors) {
      const item = document.createElement('li'), link = document.createElement('a');
      link.href = '#' + issue.field; link.textContent = issue.message;
      link.addEventListener('click', event => { event.preventDefault(); showField(issue.field); });
      item.append(link); list.append(item); get(issue.field)?.setAttribute('aria-invalid', 'true');
    }
    for (const warning of result.warnings) { const item = document.createElement('li'); item.textContent = warning; list.append(item); }
    if (list.children.length) get('validation').append(list);
    get('copy-status').textContent = '';
  }
  function updateEditor() {
    if (!editor.edited) get('command').value = editor.value;
    get('edited-status').hidden = !editor.edited;
    if (editor.edited) get('command').setAttribute('aria-describedby', 'edited-status');
    else get('command').removeAttribute('aria-describedby');
    get('active-summary').hidden = editor.edited || view() === 'advanced' || !get('active-summary').textContent;
    get('reset-command').hidden = !editor.edited;
    get('copy-command').disabled = !editor.canCopy;
    get('select-command').disabled = !editor.canCopy;
    get('validation').hidden = editor.edited;
    get('copy-status').textContent = '';
  }
  get('command').addEventListener('input', () => { editor.edit(get('command').value); updateEditor(); });
  get('reset-command').addEventListener('click', () => { editor.reset(); render(); get('command').focus(); });
  // Presets never require a fetch. Paths remain ordinary editable text.
  const groups = [['Web paths', WORDLISTS.slice(0,4)], ['HTTP inputs', WORDLISTS.slice(4,6)], ['Usernames', WORDLISTS.slice(6)]];
  for (const [label, items] of groups) {
    const group = document.createElement('optgroup'); group.label = label;
    for (const item of items) { const option = document.createElement('option'); option.value = item.id; option.textContent = item.label; group.append(option); }
    get('wordlistPreset').append(group);
  }
  get('wordlistPreset').addEventListener('change', () => {
    const item = WORDLISTS.find(item => item.id === get('wordlistPreset').value);
    if (item) get('wordlist').value = item.path;
  });
  get('wordlist').addEventListener('input', () => { get('wordlistPreset').value = 'custom'; });
  get('add-header').addEventListener('click', () => { addHeader().focus(); markCustom(); render(); });
  form.querySelectorAll('[data-profile]').forEach(button => button.addEventListener('click', () => {
    undo = { state: readState(), profile: selectedProfile, view: view(), preset: get('wordlistPreset').value };
    selectedProfile = button.dataset.profile;
    writeState({ ...readState(), ...profileChanges(selectedProfile, get('pwnbox').checked) });
    get('wordlistPreset').value = WORDLISTS.find(item => item.path === get('wordlist').value)?.id || 'custom';
    if (['deep', 'noise'].includes(selectedProfile)) {
      form.querySelector('[name="view"][value="advanced"]').checked = true;
      get(selectedProfile === 'deep' ? 'behavior-options' : 'filter-options').open = true;
    }
    get('undo-profile').hidden = false; render();
  }));
  get('undo-profile').addEventListener('click', () => {
    if (!undo) return;
    writeState(undo.state); selectedProfile = undo.profile;
    form.querySelector(`[name="view"][value="${undo.view}"]`).checked = true;
    get('wordlistPreset').value = undo.preset; undo = null; get('undo-profile').hidden = true; render();
  });
  form.addEventListener('input', event => { if (event.target.id === 'command') return; if (!['view','pwnbox'].includes(event.target.name)) markCustom(); render(); });
  form.addEventListener('change', event => { if (event.target.id === 'command') return; if (!['view','pwnbox'].includes(event.target.name)) markCustom(); render(); });
  form.addEventListener('submit', event => { event.preventDefault(); });
  get('select-command').addEventListener('click', () => { get('command').focus(); get('command').select(); get('copy-status').textContent = ''; });
  get('copy-command').addEventListener('click', async () => {
    if (!editor.canCopy) return;
    const copied = await copyCommand(editor.value, navigator.clipboard);
    if (copied) get('copy-status').textContent = 'Command copied.';
    else { get('command').focus(); get('command').select(); get('copy-status').textContent = 'Clipboard unavailable. Command selected - copy with Ctrl+C or Command+C.'; }
  });
  get('extraction-command').textContent = ROCKYOU_EXTRACT;
  get('copy-extraction').addEventListener('click', async () => {
    const copied = await copyCommand(ROCKYOU_EXTRACT, navigator.clipboard);
    get('copy-extraction').textContent = copied ? 'Copied' : 'Copy';
    if (!copied) { const selection = window.getSelection(), range = document.createRange(); range.selectNodeContents(get('extraction-command')); selection.removeAllRanges(); selection.addRange(range); }
  });
  const helps = Array.from(form.querySelectorAll('.help'));
  function closeHelp(help) { help.removeAttribute('data-open'); help.setAttribute('data-dismissed', ''); }
  for (const help of helps) {
    const button = help.querySelector('button');
    help.addEventListener('pointerenter', () => help.removeAttribute('data-dismissed'));
    button.addEventListener('focus', () => help.removeAttribute('data-dismissed'));
    button.addEventListener('click', () => {
      const open = help.hasAttribute('data-open');
      helps.forEach(closeHelp);
      if (!open) { help.removeAttribute('data-dismissed'); help.setAttribute('data-open', ''); }
    });
    help.addEventListener('focusout', event => { if (!help.contains(event.relatedTarget)) closeHelp(help); });
  }
  document.addEventListener('keydown', event => { if (event.key === 'Escape') helps.forEach(closeHelp); });
  document.addEventListener('pointerdown', event => { helps.forEach(help => { if (!help.contains(event.target)) closeHelp(help); }); });
  writeState(defaults()); render(); form.inert = false; form.removeAttribute('aria-busy');
})();
