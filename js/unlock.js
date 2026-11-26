// Unlocks the published Dido Collective site in the browser.
// Each page (and each document) is encrypted with AES-GCM, using a key derived from the
// site password with PBKDF2-SHA256. After a successful unlock the key is remembered on
// this device, so members aren't asked again on every page, until they press "Log out".
(() => {
  const STORAGE_KEY = 'dido-key';
  const payloadEl = document.getElementById('dido-payload');
  if (!payloadEl) return;

  const payload = JSON.parse(payloadEl.textContent);
  const form = document.getElementById('dido-form');
  const input = document.getElementById('password');
  const button = form.querySelector('button');
  const errorEl = document.getElementById('dido-error');
  let currentKey = null;

  const fromBase64 = (text) => Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));
  const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

  function loadKey() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      return saved ? fromBase64(saved) : null;
    } catch {
      return null;
    }
  }

  function saveKey(rawKey) {
    try {
      localStorage.setItem(STORAGE_KEY, toBase64(rawKey));
    } catch {
      // Storage unavailable (e.g. private browsing): this page still unlocks, the next one asks again.
    }
  }

  function clearKey() {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // Nothing stored.
    }
  }

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = false;
  }

  async function deriveKey(password) {
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, [
      'deriveBits',
    ]);
    return crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: fromBase64(payload.salt), iterations: payload.iterations },
      material,
      256,
    );
  }

  async function decrypt(rawKey, iv, data) {
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  }

  async function unlock(rawKey) {
    const plain = await decrypt(rawKey, fromBase64(payload.iv), fromBase64(payload.data));
    currentKey = rawKey;
    document.body.className = '';
    document.body.innerHTML = new TextDecoder().decode(plain); // the site's own pages, decrypted
    document.documentElement.classList.remove('has-key');
  }

  // Document files are stored as: 12-byte IV, then the encrypted bytes.
  async function downloadDocument(link) {
    const response = await fetch(link.href);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    const plain = await decrypt(currentKey, bytes.subarray(0, 12), bytes.subarray(12));
    const url = URL.createObjectURL(new Blob([plain], { type: link.dataset.type }));
    const a = Object.assign(document.createElement('a'), { href: url, download: link.dataset.name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!window.crypto?.subtle) {
      showError('This browser can’t open the site. Try an up-to-date Chrome, Edge, Firefox or Safari.');
      return;
    }
    button.disabled = true;
    button.textContent = 'Unlocking…';
    errorEl.hidden = true;
    try {
      const rawKey = await deriveKey(input.value);
      await unlock(rawKey);
      saveKey(rawKey);
    } catch {
      showError('That password isn’t right.');
      button.disabled = false;
      button.textContent = 'Enter';
      input.select();
    }
  });

  document.addEventListener('click', (event) => {
    const logout = event.target.closest('[data-logout]');
    if (logout) {
      clearKey();
      window.location.href = logout.dataset.logout;
      return;
    }
    const link = event.target.closest('a[data-file]');
    if (link && currentKey) {
      event.preventDefault();
      link.setAttribute('aria-busy', 'true');
      downloadDocument(link)
        .catch(() => window.alert('Sorry, that document couldn’t be opened. Please try again.'))
        .finally(() => link.removeAttribute('aria-busy'));
    }
  });

  (async () => {
    const saved = loadKey();
    if (saved && window.crypto?.subtle) {
      try {
        await unlock(saved);
        return;
      } catch {
        clearKey(); // the password has changed since this device last unlocked the site
      }
    }
    document.documentElement.classList.remove('has-key');
    input.focus();
  })();
})();
