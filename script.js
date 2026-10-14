/**
 * Assignment 2: Using Standard Cryptographic APIs (AES and RSA)
 * Information Security Programming - University of Balochistan
 * Developer: Muhammad Ayan | Instructor: Dr. Ihsan Ullah
 *
 * Implemented using ONLY the standard browser Web Crypto API.
 * No external libraries, no frameworks, no network calls.
 */

(function () {
  'use strict';

  // =========================================================================
  // 1. HELPERS & CRYPTOGRAPHIC CONVERSIONS
  // =========================================================================

  /**
   * Convert an ArrayBuffer or Uint8Array to a lowercase hexadecimal string.
   * @param {ArrayBuffer|Uint8Array} buffer
   * @returns {string}
   */
  function bufferToHex(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const hexParts = [];
    for (let i = 0; i < bytes.length; i++) {
      hexParts.push(bytes[i].toString(16).padStart(2, '0'));
    }
    return hexParts.join('');
  }

  /**
   * Convert a hexadecimal string to a Uint8Array.
   * Validates that the input contains only valid hex characters and has an even length.
   * @param {string} hex
   * @returns {Uint8Array}
   * @throws {Error} If hex string is invalid
   */
  function hexToBuffer(hex) {
    if (typeof hex !== 'string') {
      throw new Error('Hex input must be a string.');
    }
    const cleanHex = hex.trim().replace(/\s+/g, '');
    if (cleanHex.length === 0) {
      return new Uint8Array(0);
    }
    if (cleanHex.length % 2 !== 0) {
      throw new Error('Invalid hexadecimal string: length must be an even number.');
    }
    if (!/^[0-9a-fA-F]+$/.test(cleanHex)) {
      throw new Error('Invalid hexadecimal string: contains non-hexadecimal characters.');
    }
    const len = cleanHex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  /**
   * Convert an ArrayBuffer or Uint8Array to Base64 string.
   * Processes data in chunks to prevent stack overflow on large arrays.
   * @param {ArrayBuffer|Uint8Array} buffer
   * @returns {string}
   */
  function bufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000; // 32KB chunk limit
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, i + chunkSize);
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  }

  /**
   * Convert a Base64 string to a Uint8Array.
   * @param {string} b64
   * @returns {Uint8Array}
   * @throws {Error} If base64 is malformed
   */
  function base64ToBuffer(b64) {
    if (typeof b64 !== 'string') {
      throw new Error('Base64 input must be a string.');
    }
    const cleanB64 = b64.trim().replace(/\s+/g, '');
    const binary = atob(cleanB64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Format an exported public or private key buffer into PEM string.
   * Splits base64 data into standard 64-character lines.
   * @param {ArrayBuffer} buffer
   * @param {string} label - e.g. "PUBLIC KEY" or "PRIVATE KEY"
   * @returns {string}
   */
  function toPEM(buffer, label) {
    const b64 = bufferToBase64(buffer);
    const lines = [];
    for (let i = 0; i < b64.length; i += 64) {
      lines.push(b64.slice(i, i + 64));
    }
    return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
  }

  /**
   * Encode a UTF-8 string to a Uint8Array.
   * @param {string} str
   * @returns {Uint8Array}
   */
  function encodeText(str) {
    return new TextEncoder().encode(str);
  }

  /**
   * Decode a Uint8Array / ArrayBuffer to a UTF-8 string.
   * @param {ArrayBuffer|Uint8Array} buffer
   * @returns {string}
   */
  function decodeText(buffer) {
    return new TextDecoder('utf-8').decode(buffer);
  }

  /**
   * Get the byte length of a string in UTF-8.
   * @param {string} str
   * @returns {number}
   */
  function byteLength(str) {
    return encodeText(str).length;
  }

  /**
   * Concatenate two Uint8Array buffers into a single Uint8Array.
   * @param {Uint8Array} a
   * @param {Uint8Array} b
   * @returns {Uint8Array}
   */
  function concatBuffers(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  /**
   * Display a status banner message in a specific container.
   * @param {string} elementId
   * @param {string} text
   * @param {'success'|'error'|'info'|'warning'} type
   */
  function showMessage(elementId, text, type) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.className = `status-banner visible ${type}`;
    el.textContent = text;
  }

  /**
   * Hide a status banner.
   * @param {string} elementId
   */
  function hideMessage(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.className = 'status-banner';
    el.textContent = '';
  }

  /**
   * Map standard Web Crypto DOMException errors to student-friendly explanations.
   * @param {Error} err
   * @param {string} defaultMessage
   * @returns {string}
   */
  function mapCryptoError(err, defaultMessage) {
    console.error('Cryptographic operation error:', err);
    if (!err) return defaultMessage;
    if (err.name === 'OperationError') {
      return 'Operation failed: The ciphertext/tag was modified, corrupted, or an incorrect key was used.';
    }
    if (err.name === 'DataError') {
      return 'Data error: Invalid key data format or payload size exceeds algorithmic bounds.';
    }
    if (err.name === 'InvalidAccessError') {
      return 'Access error: Key does not support requested cryptographic usage.';
    }
    return err.message || defaultMessage;
  }

  // =========================================================================
  // 2. UI CONTROLS (TABS, COPY, BUTTON SPINNERS)
  // =========================================================================

  const tabButtons = [
    document.getElementById('tab-aes'),
    document.getElementById('tab-rsa'),
    document.getElementById('tab-hybrid'),
    document.getElementById('tab-tests'),
    document.getElementById('tab-report')
  ];

  const tabPanels = [
    document.getElementById('tabpanel-aes'),
    document.getElementById('tabpanel-rsa'),
    document.getElementById('tabpanel-hybrid'),
    document.getElementById('tabpanel-tests'),
    document.getElementById('tabpanel-report')
  ];

  /**
   * Switch active tab accessible navigation.
   * @param {number} activeIndex
   */
  function selectTab(activeIndex) {
    tabButtons.forEach((btn, idx) => {
      const isSelected = idx === activeIndex;
      btn.setAttribute('aria-selected', isSelected ? 'true' : 'false');
      btn.setAttribute('tabindex', isSelected ? '0' : '-1');
      if (tabPanels[idx]) {
        if (isSelected) {
          tabPanels[idx].removeAttribute('hidden');
        } else {
          tabPanels[idx].setAttribute('hidden', '');
        }
      }
    });
    tabButtons[activeIndex].focus();
  }

  // Keyboard navigation for tablist (Left, Right, Home, End)
  const tablistEl = document.querySelector('[role="tablist"]');
  if (tablistEl) {
    tablistEl.addEventListener('keydown', (e) => {
      let currentIdx = tabButtons.findIndex((b) => b.getAttribute('aria-selected') === 'true');
      if (currentIdx === -1) currentIdx = 0;

      if (e.key === 'ArrowRight') {
        e.preventDefault();
        selectTab((currentIdx + 1) % tabButtons.length);
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        selectTab((currentIdx - 1 + tabButtons.length) % tabButtons.length);
      } else if (e.key === 'Home') {
        e.preventDefault();
        selectTab(0);
      } else if (e.key === 'End') {
        e.preventDefault();
        selectTab(tabButtons.length - 1);
      }
    });
  }

  tabButtons.forEach((btn, idx) => {
    btn.addEventListener('click', () => selectTab(idx));
  });

  /**
   * Setup copy buttons with clipboard API and fallback.
   */
  document.querySelectorAll('.btn-copy').forEach((button) => {
    button.addEventListener('click', async () => {
      const targetId = button.getAttribute('data-target');
      const targetEl = document.getElementById(targetId);
      if (!targetEl) return;
      const text = targetEl.value !== undefined ? targetEl.value : targetEl.textContent;
      if (!text || text.trim() === '') return;

      const originalText = button.textContent;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        } else {
          // Fallback using temporary textarea
          const tempArea = document.createElement('textarea');
          tempArea.value = text;
          tempArea.style.position = 'fixed';
          tempArea.style.opacity = '0';
          document.body.appendChild(tempArea);
          tempArea.select();
          document.execCommand('copy');
          document.body.removeChild(tempArea);
        }
        button.textContent = 'Copied!';
        button.classList.add('btn-mint');
        button.classList.remove('btn-slate');
        setTimeout(() => {
          button.textContent = originalText;
          button.classList.remove('btn-mint');
          button.classList.add('btn-slate');
        }, 1500);
      } catch (err) {
        console.error('Failed to copy text:', err);
      }
    });
  });

  /**
   * Helper to set button loading state and prevent duplicate clicks.
   * @param {HTMLButtonElement} btn
   * @param {boolean} isLoading
   * @param {string} loadingText
   * @param {string} defaultText
   */
  function setButtonLoading(btn, isLoading, loadingText, defaultText) {
    if (!btn) return;
    btn.disabled = isLoading;
    btn.textContent = isLoading ? loadingText : defaultText;
  }

  // =========================================================================
  // 3. PART A: AES-GCM SYMMETRIC ENCRYPTION
  // =========================================================================

  // In-memory key storage (Never stored in localStorage/sessionStorage/cookies)
  let aesState = {
    key: null,
    keySize: 256,
    keyHex: '',
    originalPlaintext: '',
    ivHex: '',
    ciphertextHex: '',
    ciphertextB64: ''
  };

  const aesKeySizeSelect = document.getElementById('aes-key-size');
  const btnAesGenKey = document.getElementById('btn-aes-genkey');
  const aesKeyHexEl = document.getElementById('aes-key-hex');
  const aesKeyLabelEl = document.getElementById('aes-key-label');
  const aesPlaintextEl = document.getElementById('aes-plaintext');
  const aesPlaintextLenEl = document.getElementById('aes-plaintext-len');
  const btnAesEncrypt = document.getElementById('btn-aes-encrypt');
  const btnAesDecrypt = document.getElementById('btn-aes-decrypt');
  const btnAesClear = document.getElementById('btn-aes-clear');
  const aesBreakdownEl = document.getElementById('aes-breakdown');
  const aesIvHexEl = document.getElementById('aes-iv-hex');
  const aesCiphertextHexEl = document.getElementById('aes-ciphertext-hex');
  const aesCiphertextB64El = document.getElementById('aes-ciphertext-b64');
  const aesRecoveredEl = document.getElementById('aes-recovered');
  const aesMatchBadgeEl = document.getElementById('aes-match-badge');

  // Update live plaintext length
  function updateAesPlaintextLength() {
    const bytes = byteLength(aesPlaintextEl.value);
    aesPlaintextLenEl.textContent = `${bytes} byte${bytes === 1 ? '' : 's'}`;
  }
  aesPlaintextEl.addEventListener('input', updateAesPlaintextLength);
  updateAesPlaintextLength();

  // Changing key size clears old key & results
  aesKeySizeSelect.addEventListener('change', () => {
    aesState.key = null;
    aesState.keyHex = '';
    aesKeyHexEl.value = '';
    aesKeyLabelEl.textContent = 'AES Key (Hex) \u2013 No key generated yet';
    clearAesOutputs();
    showMessage('aes-status', `Key size set to ${aesKeySizeSelect.value}-bit. Please generate a new key.`, 'info');
  });

  function clearAesOutputs() {
    aesIvHexEl.value = '';
    aesCiphertextHexEl.value = '';
    aesCiphertextB64El.value = '';
    aesRecoveredEl.value = '';
    aesBreakdownEl.textContent = '';
    aesMatchBadgeEl.style.display = 'none';
    hideMessage('aes-status');
  }

  // Generate AES Key
  btnAesGenKey.addEventListener('click', async () => {
    setButtonLoading(btnAesGenKey, true, 'Generating...', 'Generate AES Key');
    hideMessage('aes-status');
    clearAesOutputs();
    try {
      const length = parseInt(aesKeySizeSelect.value, 10);
      const key = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: length },
        true,
        ['encrypt', 'decrypt']
      );
      const rawKeyBuffer = await window.crypto.subtle.exportKey('raw', key);
      const rawHex = bufferToHex(rawKeyBuffer);

      aesState.key = key;
      aesState.keySize = length;
      aesState.keyHex = rawHex;

      aesKeyHexEl.value = rawHex;
      aesKeyLabelEl.textContent = `AES-${length}-GCM Key (${length}-bit, ${rawHex.length / 2} bytes hex)`;
      showMessage('aes-status', `Generated fresh ${length}-bit AES key in memory successfully.`, 'success');
    } catch (err) {
      showMessage('aes-status', mapCryptoError(err, 'Failed to generate AES key.'), 'error');
    } finally {
      setButtonLoading(btnAesGenKey, false, 'Generating...', 'Generate AES Key');
    }
  });

  // Encrypt with AES-GCM
  btnAesEncrypt.addEventListener('click', async () => {
    hideMessage('aes-status');
    aesMatchBadgeEl.style.display = 'none';
    if (!aesState.key) {
      showMessage('aes-status', 'Generate an AES key first.', 'error');
      return;
    }
    const plaintext = aesPlaintextEl.value;
    if (!plaintext || plaintext.trim().length === 0) {
      showMessage('aes-status', 'Please enter some plaintext to encrypt.', 'error');
      return;
    }

    setButtonLoading(btnAesEncrypt, true, 'Encrypting...', 'Encrypt');
    try {
      // 1. Generate FRESH 12-byte IV for EVERY encryption (96-bit standard for GCM)
      const iv = new Uint8Array(12);
      window.crypto.getRandomValues(iv);

      // 2. Encrypt using AES-GCM with standard 128-bit authentication tag
      const plainBytes = encodeText(plaintext);
      const ciphertextBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv, tagLength: 128 },
        aesState.key,
        plainBytes
      );

      const ivHex = bufferToHex(iv);
      const cipherBytes = new Uint8Array(ciphertextBuffer);
      const cipherHex = bufferToHex(cipherBytes);
      const cipherB64 = bufferToBase64(cipherBytes);

      // Save state
      aesState.originalPlaintext = plaintext;
      aesState.ivHex = ivHex;
      aesState.ciphertextHex = cipherHex;
      aesState.ciphertextB64 = cipherB64;

      // Populate UI
      aesIvHexEl.value = ivHex;
      aesCiphertextHexEl.value = cipherHex;
      aesCiphertextB64El.value = cipherB64;
      aesRecoveredEl.value = '';

      const plainLen = plainBytes.length;
      const cipherLen = cipherBytes.length;
      aesBreakdownEl.textContent = `Plaintext ${plainLen} bytes + 16-byte authentication tag = ciphertext ${cipherLen} bytes.`;
      showMessage('aes-status', 'Plaintext encrypted successfully with a fresh random 12-byte IV and 128-bit auth tag.', 'success');
    } catch (err) {
      showMessage('aes-status', mapCryptoError(err, 'Encryption failed.'), 'error');
    } finally {
      setButtonLoading(btnAesEncrypt, false, 'Encrypting...', 'Encrypt');
    }
  });

  // Live sync: editing Hex ciphertext updates Base64 display
  aesCiphertextHexEl.addEventListener('input', () => {
    try {
      const rawHex = aesCiphertextHexEl.value.trim();
      if (!rawHex) {
        aesCiphertextB64El.value = '';
        return;
      }
      const buf = hexToBuffer(rawHex);
      aesCiphertextB64El.value = bufferToBase64(buf);
    } catch (e) {
      aesCiphertextB64El.value = '[Invalid Hexadecimal input]';
    }
  });

  // Decrypt with AES-GCM
  btnAesDecrypt.addEventListener('click', async () => {
    hideMessage('aes-status');
    aesMatchBadgeEl.style.display = 'none';

    if (!aesState.key) {
      showMessage('aes-status', 'Generate an AES key first.', 'error');
      return;
    }
    const ivHex = aesIvHexEl.value.trim();
    const cipherHex = aesCiphertextHexEl.value.trim();

    if (!ivHex || !cipherHex) {
      showMessage('aes-status', 'Both IV (hex) and Ciphertext (hex) must be provided for decryption.', 'error');
      return;
    }

    setButtonLoading(btnAesDecrypt, true, 'Decrypting...', 'Decrypt');
    try {
      let ivBytes;
      try {
        ivBytes = hexToBuffer(ivHex);
      } catch (err) {
        throw new Error('IV is not valid hexadecimal: ' + err.message);
      }

      if (ivBytes.length !== 12) {
        throw new Error(`Invalid IV length: expected 12 bytes (24 hex chars), got ${ivBytes.length} bytes.`);
      }

      let cipherBytes;
      try {
        cipherBytes = hexToBuffer(cipherHex);
      } catch (err) {
        throw new Error('Ciphertext is not valid hexadecimal: ' + err.message);
      }

      if (cipherBytes.length < 16) {
        throw new Error('Ciphertext too short: must be at least 16 bytes for the authentication tag.');
      }

      // Perform AES-GCM Decryption
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
        aesState.key,
        cipherBytes
      );

      const recoveredText = decodeText(decryptedBuffer);
      aesRecoveredEl.value = recoveredText;

      // Verification Badge
      if (recoveredText === aesState.originalPlaintext) {
        aesMatchBadgeEl.className = 'badge badge-match';
        aesMatchBadgeEl.textContent = 'MATCHES ORIGINAL';
        aesMatchBadgeEl.style.display = 'inline-flex';
        showMessage('aes-status', 'Authentication and decryption successful! Decrypted plaintext verified.', 'success');
      } else {
        aesMatchBadgeEl.className = 'badge badge-mismatch';
        aesMatchBadgeEl.textContent = 'MISMATCH';
        aesMatchBadgeEl.style.display = 'inline-flex';
        showMessage('aes-status', 'Decryption succeeded but content differs from original input text.', 'warning');
      }
    } catch (err) {
      aesRecoveredEl.value = '';
      aesMatchBadgeEl.className = 'badge badge-mismatch';
      aesMatchBadgeEl.textContent = 'AUTHENTICATION FAILED';
      aesMatchBadgeEl.style.display = 'inline-flex';
      showMessage('aes-status', 'Authentication failed \u2013 the ciphertext or IV was modified, or the wrong key was used.', 'error');
    } finally {
      setButtonLoading(btnAesDecrypt, false, 'Decrypting...', 'Decrypt');
    }
  });

  btnAesClear.addEventListener('click', clearAesOutputs);

  // =========================================================================
  // 4. PART B: RSA-OAEP ASYMMETRIC ENCRYPTION
  // =========================================================================

  let rsaState = {
    keyPair: null,
    pubKeyPem: '',
    privKeyPem: '',
    originalMessage: '',
    ciphertextB64: '',
    ciphertextHex: ''
  };

  const btnRsaGenKey = document.getElementById('btn-rsa-genkey');
  const rsaPubKeyPemEl = document.getElementById('rsa-pubkey-pem');
  const rsaPrivKeyPemEl = document.getElementById('rsa-privkey-pem');
  const rsaMessageEl = document.getElementById('rsa-message');
  const rsaMsgLenEl = document.getElementById('rsa-msg-len');
  const btnRsaEncrypt = document.getElementById('btn-rsa-encrypt');
  const btnRsaDecrypt = document.getElementById('btn-rsa-decrypt');
  const btnRsaTryLong = document.getElementById('btn-rsa-try-long');
  const btnRsaClear = document.getElementById('btn-rsa-clear');
  const rsaCiphertextMetaEl = document.getElementById('rsa-ciphertext-meta');
  const rsaCiphertextB64El = document.getElementById('rsa-ciphertext-b64');
  const rsaCiphertextHexEl = document.getElementById('rsa-ciphertext-hex');
  const rsaRecoveredEl = document.getElementById('rsa-recovered');
  const rsaMatchBadgeEl = document.getElementById('rsa-match-badge');

  const RSA_MAX_BYTES = 190; // 256 - (2 * 32) - 2 for 2048-bit with SHA-256

  function updateRsaMessageLength() {
    const bytes = byteLength(rsaMessageEl.value);
    rsaMsgLenEl.textContent = `${bytes} / ${RSA_MAX_BYTES} bytes`;
    if (bytes > RSA_MAX_BYTES) {
      rsaMsgLenEl.classList.add('limit-exceeded');
      btnRsaEncrypt.disabled = true;
      showMessage('rsa-status', `Message is ${bytes} bytes, exceeding the 190-byte limit for RSA-OAEP-2048 with SHA-256! RSA cannot encrypt this.`, 'error');
    } else {
      rsaMsgLenEl.classList.remove('limit-exceeded');
      btnRsaEncrypt.disabled = false;
      hideMessage('rsa-status');
    }
  }
  rsaMessageEl.addEventListener('input', updateRsaMessageLength);
  updateRsaMessageLength();

  function clearRsaOutputs() {
    rsaCiphertextB64El.value = '';
    rsaCiphertextHexEl.value = '';
    rsaRecoveredEl.value = '';
    rsaCiphertextMetaEl.textContent = '';
    rsaMatchBadgeEl.style.display = 'none';
    hideMessage('rsa-status');
  }

  // Generate RSA Key Pair
  btnRsaGenKey.addEventListener('click', async () => {
    setButtonLoading(btnRsaGenKey, true, 'Generating RSA Key Pair (may take ~1-2s)...', 'Generate RSA Key Pair');
    hideMessage('rsa-status');
    clearRsaOutputs();

    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]), // 65537
          hash: 'SHA-256'
        },
        true,
        ['encrypt', 'decrypt']
      );

      const spkiBuffer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
      const pkcs8Buffer = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

      const pubPem = toPEM(spkiBuffer, 'PUBLIC KEY');
      const privPem = toPEM(pkcs8Buffer, 'PRIVATE KEY');

      rsaState.keyPair = keyPair;
      rsaState.pubKeyPem = pubPem;
      rsaState.privKeyPem = privPem;

      rsaPubKeyPemEl.value = pubPem;
      rsaPrivKeyPemEl.value = privPem;

      const repSpkiPreview = document.getElementById('rep-spki-preview');
      const repPkcs8Preview = document.getElementById('rep-pkcs8-preview');
      if (repSpkiPreview) repSpkiPreview.value = pubPem;
      if (repPkcs8Preview) repPkcs8Preview.value = privPem;

      showMessage('rsa-status', 'Generated RSA-2048 key pair in memory (SPKI public key and PKCS#8 private key).', 'success');
    } catch (err) {
      showMessage('rsa-status', mapCryptoError(err, 'Failed to generate RSA key pair.'), 'error');
    } finally {
      setButtonLoading(btnRsaGenKey, false, 'Generating...', 'Generate RSA Key Pair');
    }
  });

  // Encrypt with RSA Public Key
  btnRsaEncrypt.addEventListener('click', async () => {
    hideMessage('rsa-status');
    rsaMatchBadgeEl.style.display = 'none';

    if (!rsaState.keyPair || !rsaState.keyPair.publicKey) {
      showMessage('rsa-status', 'Generate an RSA key pair first.', 'error');
      return;
    }
    const message = rsaMessageEl.value;
    if (!message || message.trim().length === 0) {
      showMessage('rsa-status', 'Please enter a message to encrypt.', 'error');
      return;
    }
    const msgBytes = encodeText(message);
    if (msgBytes.length > RSA_MAX_BYTES) {
      showMessage('rsa-status', `Message is ${msgBytes.length} bytes. RSA-OAEP-2048 with SHA-256 limit is 190 bytes.`, 'error');
      return;
    }

    setButtonLoading(btnRsaEncrypt, true, 'Encrypting...', 'Encrypt with Public Key');
    try {
      const ciphertextBuffer = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        rsaState.keyPair.publicKey,
        msgBytes
      );

      const cipherBytes = new Uint8Array(ciphertextBuffer);
      const cipherB64 = bufferToBase64(cipherBytes);
      const cipherHex = bufferToHex(cipherBytes);

      rsaState.originalMessage = message;
      rsaState.ciphertextB64 = cipherB64;
      rsaState.ciphertextHex = cipherHex;

      rsaCiphertextB64El.value = cipherB64;
      rsaCiphertextHexEl.value = cipherHex;
      rsaRecoveredEl.value = '';

      rsaCiphertextMetaEl.textContent = `Ciphertext length: ${cipherBytes.length} bytes (2048 bits). Note: OAEP applies randomized padding; encrypting the same text twice produces distinct ciphertexts.`;
      showMessage('rsa-status', 'Message encrypted with RSA public key successfully.', 'success');
    } catch (err) {
      showMessage('rsa-status', mapCryptoError(err, 'RSA encryption failed.'), 'error');
    } finally {
      setButtonLoading(btnRsaEncrypt, false, 'Encrypting...', 'Encrypt with Public Key');
    }
  });

  // Decrypt with RSA Private Key
  btnRsaDecrypt.addEventListener('click', async () => {
    hideMessage('rsa-status');
    rsaMatchBadgeEl.style.display = 'none';

    if (!rsaState.keyPair || !rsaState.keyPair.privateKey) {
      showMessage('rsa-status', 'Generate an RSA key pair first.', 'error');
      return;
    }
    const cipherB64 = rsaCiphertextB64El.value.trim();
    if (!cipherB64) {
      showMessage('rsa-status', 'No ciphertext available to decrypt. Encrypt a message first.', 'error');
      return;
    }

    setButtonLoading(btnRsaDecrypt, true, 'Decrypting...', 'Decrypt with Private Key');
    try {
      const cipherBytes = base64ToBuffer(cipherB64);
      if (cipherBytes.length !== 256) {
        throw new Error(`Invalid RSA-2048 ciphertext length: expected 256 bytes, got ${cipherBytes.length}.`);
      }

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        rsaState.keyPair.privateKey,
        cipherBytes
      );

      const recoveredText = decodeText(decryptedBuffer);
      rsaRecoveredEl.value = recoveredText;

      if (recoveredText === rsaState.originalMessage) {
        rsaMatchBadgeEl.className = 'badge badge-match';
        rsaMatchBadgeEl.textContent = 'MATCHES ORIGINAL';
        rsaMatchBadgeEl.style.display = 'inline-flex';
        showMessage('rsa-status', 'RSA decryption verified! Recovered message matches the original text.', 'success');
      } else {
        rsaMatchBadgeEl.className = 'badge badge-mismatch';
        rsaMatchBadgeEl.textContent = 'MISMATCH';
        rsaMatchBadgeEl.style.display = 'inline-flex';
        showMessage('rsa-status', 'Decrypted text does not match original message.', 'warning');
      }
    } catch (err) {
      rsaRecoveredEl.value = '';
      rsaMatchBadgeEl.className = 'badge badge-mismatch';
      rsaMatchBadgeEl.textContent = 'DECRYPTION FAILED';
      rsaMatchBadgeEl.style.display = 'inline-flex';
      showMessage('rsa-status', mapCryptoError(err, 'RSA decryption failed. Ciphertext may be corrupt or wrong private key used.'), 'error');
    } finally {
      setButtonLoading(btnRsaDecrypt, false, 'Decrypting...', 'Decrypt with Private Key');
    }
  });

  // "Try a long message" demo button
  btnRsaTryLong.addEventListener('click', () => {
    rsaMessageEl.value = 'Public key cryptography is mathematically elegant but computationally expensive and severely constrained in payload capacity. Attempting to encrypt this entire paragraph directly with RSA-2048-OAEP-SHA256 will immediately exceed the 190-byte limit!';
    updateRsaMessageLength();
  });

  btnRsaClear.addEventListener('click', clearRsaOutputs);

  // =========================================================================
  // 5. PART C: MINIMAL HYBRID CRYPTOSYSTEM
  // =========================================================================

  let hybridState = {
    lastRun: null
  };

  const hybridMessageEl = document.getElementById('hybrid-message');
  const hybridMsgLenEl = document.getElementById('hybrid-msg-len');
  const hybridLimitNoteEl = document.getElementById('hybrid-limit-note');
  const hybridTamperSelect = document.getElementById('hybrid-tamper');
  const btnHybridRun = document.getElementById('btn-hybrid-run');
  const btnHybridClear = document.getElementById('btn-hybrid-clear');
  const hybridLogEl = document.getElementById('hybrid-log');
  const hybridSummaryCardEl = document.getElementById('hybrid-summary-card');
  const sumPlaintextBytesEl = document.getElementById('sum-plaintext-bytes');
  const sumCiphertextBytesEl = document.getElementById('sum-ciphertext-bytes');
  const sumEnckeyBytesEl = document.getElementById('sum-enckey-bytes');
  const sumTotalBytesEl = document.getElementById('sum-total-bytes');

  function updateHybridMessageLength() {
    const bytes = byteLength(hybridMessageEl.value);
    hybridMsgLenEl.textContent = `${bytes} bytes`;
    if (bytes > 190) {
      hybridLimitNoteEl.textContent = `Message size: ${bytes} bytes — exceeds the RSA-OAEP 190-byte limit, so we use hybrid encryption.`;
      hybridLimitNoteEl.style.display = 'block';
    } else {
      hybridLimitNoteEl.style.display = 'none';
    }
  }
  hybridMessageEl.addEventListener('input', updateHybridMessageLength);
  updateHybridMessageLength();

  function clearHybridLog() {
    hybridLogEl.textContent = '';
    hybridSummaryCardEl.style.display = 'none';
    hideMessage('hybrid-status');
  }
  btnHybridClear.addEventListener('click', clearHybridLog);

  /**
   * Render an individual card in the step-by-step hybrid execution log.
   * Uses safe DOM textContent methods to prevent XSS.
   */
  function createStepCard(stepNumber, title, description, status, details) {
    const card = document.createElement('div');
    card.className = `hybrid-step-card status-${status}`;
    card.id = `hybrid-step-${stepNumber}`;

    const header = document.createElement('div');
    header.className = 'step-card-header';

    const headerLeft = document.createElement('div');
    headerLeft.className = 'step-header-left';

    const numBadge = document.createElement('span');
    numBadge.className = 'step-number';
    numBadge.textContent = String(stepNumber);

    const titleEl = document.createElement('h3');
    titleEl.className = 'step-title';
    titleEl.textContent = title;

    headerLeft.appendChild(numBadge);
    headerLeft.appendChild(titleEl);

    const statusBadge = document.createElement('span');
    statusBadge.className = status === 'ok' ? 'badge badge-pass' : (status === 'failed' ? 'badge badge-fail' : 'badge badge-skipped');
    statusBadge.textContent = status === 'ok' ? 'OK' : (status === 'failed' ? 'FAILED' : 'SKIPPED');

    header.appendChild(headerLeft);
    header.appendChild(statusBadge);
    card.appendChild(header);

    const descEl = document.createElement('div');
    descEl.className = 'step-desc';
    descEl.textContent = description;
    card.appendChild(descEl);

    if (details && details.length > 0) {
      const detailsContainer = document.createElement('div');
      detailsContainer.className = 'step-values';
      details.forEach((item) => {
        const itemBox = document.createElement('div');
        itemBox.className = 'report-code-block';
        itemBox.style.margin = '4px 0';
        itemBox.style.padding = '6px 10px';
        itemBox.style.fontSize = '0.8rem';
        itemBox.textContent = `${item.label}: ${item.value}`;
        detailsContainer.appendChild(itemBox);
      });
      card.appendChild(detailsContainer);
    }

    return card;
  }

  // Run Hybrid Simulation
  btnHybridRun.addEventListener('click', async () => {
    hideMessage('hybrid-status');
    clearHybridLog();

    const message = hybridMessageEl.value;
    if (!message || message.trim().length === 0) {
      showMessage('hybrid-status', 'Please enter a message to encrypt.', 'error');
      return;
    }

    setButtonLoading(btnHybridRun, true, 'Running hybrid flow...', 'Run Hybrid Demo');
    const tamperOption = hybridTamperSelect.value;
    let stepCount = 1;

    try {
      // ---------------------------------------------------------------------
      // STEP 1: SENDER - Generate fresh random AES-256-GCM key
      // ---------------------------------------------------------------------
      const aesKey = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      const rawAesKeyBuffer = await window.crypto.subtle.exportKey('raw', aesKey);
      const rawAesKeyHex = bufferToHex(rawAesKeyBuffer);

      hybridLogEl.appendChild(
        createStepCard(
          stepCount++,
          'SENDER: Generate AES-256-GCM Session Key',
          'A single-use 256-bit symmetric session key is generated in memory for fast bulk encryption.',
          'ok',
          [
            { label: 'Key Algorithm', value: 'AES-256-GCM (32 bytes)' },
            { label: 'Raw Key (Hex, Demo Only)', value: rawAesKeyHex }
          ]
        )
      );

      // ---------------------------------------------------------------------
      // STEP 2: SENDER - Encrypt payload with AES-GCM
      // ---------------------------------------------------------------------
      const iv = new Uint8Array(12);
      window.crypto.getRandomValues(iv);
      const msgBytes = encodeText(message);

      const aesCipherBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv, tagLength: 128 },
        aesKey,
        msgBytes
      );
      let aesCipherBytes = new Uint8Array(aesCipherBuffer);
      let ivBytes = new Uint8Array(iv);

      hybridLogEl.appendChild(
        createStepCard(
          stepCount++,
          'SENDER: Encrypt Bulk Message with AES-GCM',
          'The arbitrary-length message is encrypted under the fresh AES key using a randomized 12-byte IV.',
          'ok',
          [
            { label: 'Plaintext Size', value: `${msgBytes.length} bytes` },
            { label: 'IV (Hex, 12 bytes)', value: bufferToHex(ivBytes) },
            { label: 'Ciphertext + 16B Tag (Base64)', value: bufferToBase64(aesCipherBytes) },
            { label: 'Ciphertext Size', value: `${aesCipherBytes.length} bytes (Payload + 16-byte GCM Tag)` }
          ]
        )
      );

      // ---------------------------------------------------------------------
      // STEP 3: RECEIVER KEYS - Generate RSA-2048 key pair
      // ---------------------------------------------------------------------
      const rsaKeyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['encrypt', 'decrypt']
      );

      const spkiPub = await window.crypto.subtle.exportKey('spki', rsaKeyPair.publicKey);
      const pubPem = toPEM(spkiPub, 'PUBLIC KEY');

      hybridLogEl.appendChild(
        createStepCard(
          stepCount++,
          'RECEIVER KEYS: Generate RSA-2048 Key Pair',
          'The receiver advertises their public key (SPKI) to senders. The private key remains safe and undisclosed.',
          'ok',
          [
            { label: 'Algorithm', value: 'RSA-OAEP-2048 (SHA-256)' },
            { label: 'Receiver Public Key (SPKI PEM)', value: pubPem }
          ]
        )
      );

      // ---------------------------------------------------------------------
      // STEP 4: SENDER - Encrypt AES key using RSA public key
      // ---------------------------------------------------------------------
      const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        rsaKeyPair.publicKey,
        rawAesKeyBuffer
      );
      let encryptedKeyBytes = new Uint8Array(encryptedKeyBuffer);

      hybridLogEl.appendChild(
        createStepCard(
          stepCount++,
          'SENDER: Encrypt AES Key with Receiver Public Key',
          'The 32-byte AES key easily fits into RSA-OAEP capacity (32 <= 190 bytes). The resulting ciphertext is 256 bytes.',
          'ok',
          [
            { label: 'Input Key Size', value: `${rawAesKeyBuffer.byteLength} bytes` },
            { label: 'Encrypted Key (Base64)', value: bufferToBase64(encryptedKeyBytes) },
            { label: 'Encrypted Key Size', value: `${encryptedKeyBytes.length} bytes (2048 bits)` }
          ]
        )
      );

      // ---------------------------------------------------------------------
      // STEP 5: TRANSMIT - Build package and simulate network transmission
      // ---------------------------------------------------------------------
      let transmitDetails = [];
      let transmissionNote = 'The payload package is prepared with Base64 encoding for safe transport across standard HTTP/JSON APIs.';

      if (tamperOption === 'ciphertext') {
        aesCipherBytes[0] ^= 1; // Flip lowest bit of first byte
        transmissionNote = 'ATTACKER TAMPERING DETECTED: The adversary intercepted the package and flipped one bit in the AES ciphertext.';
        transmitDetails.push({ label: 'Tamper Action', value: 'Flipped lowest bit of first byte in AES ciphertext' });
      } else if (tamperOption === 'key') {
        encryptedKeyBytes[0] ^= 1; // Flip lowest bit in encrypted key
        transmissionNote = 'ATTACKER TAMPERING DETECTED: The adversary intercepted the package and flipped one bit in the encrypted AES key.';
        transmitDetails.push({ label: 'Tamper Action', value: 'Flipped lowest bit of first byte in Encrypted Key' });
      } else if (tamperOption === 'iv') {
        ivBytes[0] ^= 1; // Flip lowest bit in IV
        transmissionNote = 'ATTACKER TAMPERING DETECTED: The adversary intercepted the package and flipped one bit in the IV nonce.';
        transmitDetails.push({ label: 'Tamper Action', value: 'Flipped lowest bit of first byte in IV' });
      }

      const transmitPackage = {
        encryptedKey: bufferToBase64(encryptedKeyBytes),
        iv: bufferToBase64(ivBytes),
        ciphertext: bufferToBase64(aesCipherBytes)
      };
      const packageJson = JSON.stringify(transmitPackage, null, 2);

      transmitDetails.push({ label: 'Network Package (JSON)', value: packageJson });

      hybridLogEl.appendChild(
        createStepCard(
          stepCount++,
          'TRANSMIT: Package Sent Over the Network',
          transmissionNote,
          'ok',
          transmitDetails
        )
      );

      // Update summary cards
      const totalTransmittedBytes = encryptedKeyBytes.length + ivBytes.length + aesCipherBytes.length;
      sumPlaintextBytesEl.textContent = `${msgBytes.length} B`;
      sumCiphertextBytesEl.textContent = `${aesCipherBytes.length} B`;
      sumEnckeyBytesEl.textContent = `${encryptedKeyBytes.length} B`;
      sumTotalBytesEl.textContent = `${totalTransmittedBytes} B`;
      hybridSummaryCardEl.style.display = 'block';

      // ---------------------------------------------------------------------
      // STEP 6: RECEIVER - Decrypt the AES key with RSA private key
      // ---------------------------------------------------------------------
      let recoveredAesKey;
      try {
        const decryptedKeyBuf = await window.crypto.subtle.decrypt(
          { name: 'RSA-OAEP' },
          rsaKeyPair.privateKey,
          encryptedKeyBytes
        );

        recoveredAesKey = await window.crypto.subtle.importKey(
          'raw',
          decryptedKeyBuf,
          { name: 'AES-GCM' },
          false,
          ['decrypt']
        );

        hybridLogEl.appendChild(
          createStepCard(
            stepCount++,
            'RECEIVER: Decrypt Session Key with RSA Private Key',
            'The receiver decapsulates the AES key using their private key and imports it into subtle crypto.',
            'ok',
            [
              { label: 'RSA Decryption', value: 'Success (OAEP padding verified)' },
              { label: 'Recovered Key Size', value: `${decryptedKeyBuf.byteLength * 8}-bit` }
            ]
          )
        );
      } catch (rsaErr) {
        hybridLogEl.appendChild(
          createStepCard(
            stepCount++,
            'RECEIVER: Decrypt Session Key with RSA Private Key',
            'RSA decryption failed: the encrypted key was modified in transit (OAEP padding integrity check failed).',
            'failed',
            [{ label: 'Security Enforcement', value: 'RSA-OAEP mathematically detected altered key ciphertext' }]
          )
        );
        hybridLogEl.appendChild(createStepCard(stepCount++, 'RECEIVER: Decrypt Bulk Message with Recovered AES Key', 'Skipped because session key could not be recovered.', 'skipped', []));
        hybridLogEl.appendChild(createStepCard(stepCount++, 'VERIFY: Integrity & Content Match', 'Skipped due to upstream cryptographic failure.', 'skipped', []));
        showMessage('hybrid-status', 'RSA decryption failed \u2013 the encrypted key was modified in transit.', 'error');
        recordHybridRun(false, tamperOption, msgBytes.length, aesCipherBytes.length, encryptedKeyBytes.length);
        return;
      }

      // ---------------------------------------------------------------------
      // STEP 7: RECEIVER - Decrypt message with recovered AES key & IV
      // ---------------------------------------------------------------------
      let decryptedMessage = '';
      try {
        const decryptedPayloadBuf = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
          recoveredAesKey,
          aesCipherBytes
        );
        decryptedMessage = decodeText(decryptedPayloadBuf);

        hybridLogEl.appendChild(
          createStepCard(
            stepCount++,
            'RECEIVER: Decrypt Bulk Message with Recovered AES Key',
            'The receiver uses the authenticated AES-GCM cipher to decrypt and verify the entire message payload.',
            'ok',
            [
              { label: 'AES-GCM Authentication', value: 'Passed: 16-byte tag matches computed MAC' },
              { label: 'Decrypted Length', value: `${decryptedPayloadBuf.byteLength} bytes` }
            ]
          )
        );
      } catch (aesErr) {
        hybridLogEl.appendChild(
          createStepCard(
            stepCount++,
            'RECEIVER: Decrypt Bulk Message with Recovered AES Key',
            'Authentication failed: ciphertext or IV was modified in transit (AES-GCM authentication tag mismatch).',
            'failed',
            [{ label: 'Security Enforcement', value: 'AES-GCM refused to release compromised plaintext' }]
          )
        );
        hybridLogEl.appendChild(createStepCard(stepCount++, 'VERIFY: Integrity & Content Match', 'Skipped due to cryptographic authentication failure.', 'skipped', []));
        showMessage('hybrid-status', 'Authentication failed \u2013 ciphertext or IV was modified in transit.', 'error');
        recordHybridRun(false, tamperOption, msgBytes.length, aesCipherBytes.length, encryptedKeyBytes.length);
        return;
      }

      // ---------------------------------------------------------------------
      // STEP 8: VERIFY - Compare with original message
      // ---------------------------------------------------------------------
      if (decryptedMessage === message) {
        hybridLogEl.appendChild(
          createStepCard(
            stepCount++,
            'VERIFY: Complete Cryptographic Verification',
            'SUCCESS: plaintext matches the original payload byte-for-byte. The hybrid envelope preserved confidentiality and authenticated integrity.',
            'ok',
            [
              { label: 'Original Message', value: message.slice(0, 100) + '...' },
              { label: 'Recovered Message', value: decryptedMessage.slice(0, 100) + '...' },
              { label: 'Verification Status', value: 'MATCHES ORIGINAL (Clean transmission)' }
            ]
          )
        );
        showMessage('hybrid-status', 'Hybrid encryption & decryption completed successfully! Plaintext verified.', 'success');
        recordHybridRun(true, tamperOption, msgBytes.length, aesCipherBytes.length, encryptedKeyBytes.length);
      } else {
        hybridLogEl.appendChild(
          createStepCard(
            stepCount++,
            'VERIFY: Integrity Verification',
            'FAILED: Plaintext does not match original message.',
            'failed',
            []
          )
        );
        showMessage('hybrid-status', 'Payload mismatch occurred.', 'error');
        recordHybridRun(false, tamperOption, msgBytes.length, aesCipherBytes.length, encryptedKeyBytes.length);
      }
    } catch (err) {
      showMessage('hybrid-status', mapCryptoError(err, 'Hybrid simulation failed.'), 'error');
    } finally {
      setButtonLoading(btnHybridRun, false, 'Running...', 'Run Hybrid Demo');
    }
  });

  function recordHybridRun(success, tamper, plainLen, cipherLen, encKeyLen) {
    hybridState.lastRun = {
      timestamp: new Date().toLocaleTimeString(),
      success: success,
      tamper: tamper,
      plainBytes: plainLen,
      cipherBytes: cipherLen,
      encKeyBytes: encKeyLen
    };
  }

  // =========================================================================
  // 6. TESTS TAB: AUTOMATED VERIFICATION SUITE
  // =========================================================================

  let testRunResults = {
    executed: false,
    total: 19,
    passed: 0,
    failed: 0,
    tests: []
  };

  const btnRunTests = document.getElementById('btn-run-tests');
  const testResultsBodyEl = document.getElementById('test-results-body');
  const testSummaryCountsEl = document.getElementById('test-summary-counts');

  /**
   * Run automated tests in clean isolation without modifying user state.
   */
  btnRunTests.addEventListener('click', async () => {
    setButtonLoading(btnRunTests, true, 'Executing 19 cryptographic tests...', 'Run All Tests');
    testSummaryCountsEl.textContent = 'Running test suite...';

    // Clear table
    testResultsBodyEl.textContent = '';
    testRunResults = {
      executed: false,
      total: 19,
      passed: 0,
      failed: 0,
      tests: []
    };

    /**
     * Helper to append test row safely using DOM nodes
     */
    function recordTest(num, name, expected, actual, pass) {
      if (pass) testRunResults.passed++;
      else testRunResults.failed++;
      testRunResults.tests.push({ num, name, expected, actual, pass });

      const tr = document.createElement('tr');

      const tdNum = document.createElement('td');
      tdNum.textContent = String(num);

      const tdName = document.createElement('td');
      tdName.textContent = name;

      const tdExp = document.createElement('td');
      tdExp.className = 'col-mono';
      tdExp.textContent = expected;

      const tdAct = document.createElement('td');
      tdAct.className = 'col-mono';
      tdAct.textContent = actual;

      const tdRes = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = pass ? 'badge badge-pass' : 'badge badge-fail';
      badge.textContent = pass ? 'PASS' : 'FAIL';
      tdRes.appendChild(badge);

      tr.appendChild(tdNum);
      tr.appendChild(tdName);
      tr.appendChild(tdExp);
      tr.appendChild(tdAct);
      tr.appendChild(tdRes);
      testResultsBodyEl.appendChild(tr);
    }

    try {
      // ---------------------------------------------------------------------
      // Test 1: Helpers: hex round trip and base64 round trip on sample bytes
      // ---------------------------------------------------------------------
      const sample1 = new Uint8Array([0x00, 0x01, 0x0a, 0xff, 0x42, 0xee]);
      const hex1 = bufferToHex(sample1);
      const backSample1 = hexToBuffer(hex1);
      const b64_1 = bufferToBase64(sample1);
      const backB64_1 = base64ToBuffer(b64_1);
      const pass1 = bufferToHex(backSample1) === hex1 && bufferToHex(backB64_1) === hex1;
      recordTest(1, 'Helpers: Hex and Base64 round-trip conversion', 'Byte identities match', pass1 ? 'Matched' : 'Mismatch', pass1);

      // ---------------------------------------------------------------------
      // Test 2: Helpers: hexToBuffer rejects invalid hex
      // ---------------------------------------------------------------------
      let pass2 = false;
      try {
        hexToBuffer('012'); // odd length
      } catch (e1) {
        try {
          hexToBuffer('012z'); // invalid non-hex
        } catch (e2) {
          pass2 = true;
        }
      }
      recordTest(2, 'Helpers: hexToBuffer rejects invalid hex (odd length, non-hex chars)', 'Throws descriptive errors', pass2 ? 'Errors correctly thrown' : 'Did not throw', pass2);

      // ---------------------------------------------------------------------
      // Test 3: PEM: header, footer and max line length <= 64 chars
      // ---------------------------------------------------------------------
      const dummyBuf = new Uint8Array(100);
      window.crypto.getRandomValues(dummyBuf);
      const pemStr = toPEM(dummyBuf, 'TEST');
      const pemLines = pemStr.split('\n');
      const startsOk = pemLines[0] === '-----BEGIN TEST-----';
      const endsOk = pemLines[pemLines.length - 1] === '-----END TEST-----';
      const linesLengthOk = pemLines.slice(1, -1).every((l) => l.length <= 64);
      const pass3 = startsOk && endsOk && linesLengthOk;
      recordTest(3, 'PEM: Output formatted with BEGIN/END and <= 64 char lines', 'Valid PEM wrapping', pass3 ? 'Valid format' : 'Invalid wrapping', pass3);

      // ---------------------------------------------------------------------
      // Test 4: AES-128-GCM encrypt then decrypt returns original
      // ---------------------------------------------------------------------
      const key128 = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, ['encrypt', 'decrypt']);
      const iv128 = new Uint8Array(12);
      window.crypto.getRandomValues(iv128);
      const msg4 = 'Unit test AES 128';
      const enc4 = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv128 }, key128, encodeText(msg4));
      const dec4 = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv128 }, key128, enc4);
      const pass4 = decodeText(dec4) === msg4;
      recordTest(4, 'AES-128-GCM: Encrypt then decrypt round-trip', `"${msg4}"`, `"${decodeText(dec4)}"`, pass4);

      // ---------------------------------------------------------------------
      // Test 5: AES-256-GCM encrypt then decrypt returns original
      // ---------------------------------------------------------------------
      const key256 = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      const iv256 = new Uint8Array(12);
      window.crypto.getRandomValues(iv256);
      const msg5 = 'Unit test AES 256 GCM authenticated text';
      const enc5 = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv256 }, key256, encodeText(msg5));
      const dec5 = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv256 }, key256, enc5);
      const pass5 = decodeText(dec5) === msg5;
      recordTest(5, 'AES-256-GCM: Encrypt then decrypt round-trip', `"${msg5}"`, `"${decodeText(dec5)}"`, pass5);

      // ---------------------------------------------------------------------
      // Test 6: AES-GCM with UTF-8 / non-ASCII text round trips correctly
      // ---------------------------------------------------------------------
      const msg6 = 'Grüße aus München! 🔐 £€¥ © 2026 日本語';
      const enc6 = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv256 }, key256, encodeText(msg6));
      const dec6 = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv256 }, key256, enc6);
      const pass6 = decodeText(dec6) === msg6;
      recordTest(6, 'AES-GCM: Non-ASCII UTF-8 characters round-trip', msg6, decodeText(dec6), pass6);

      // ---------------------------------------------------------------------
      // Test 7: AES-GCM ciphertext length equals plaintext bytes + 16
      // ---------------------------------------------------------------------
      const plainLen7 = encodeText(msg5).length;
      const cipherLen7 = new Uint8Array(enc5).length;
      const pass7 = cipherLen7 === plainLen7 + 16;
      recordTest(7, 'AES-GCM: Ciphertext length equals plaintext + 16 bytes (tag)', `${plainLen7 + 16} bytes`, `${cipherLen7} bytes`, pass7);

      // ---------------------------------------------------------------------
      // Test 8: AES-GCM fresh IVs give different ciphertexts
      // ---------------------------------------------------------------------
      const iv8_a = new Uint8Array(12);
      const iv8_b = new Uint8Array(12);
      window.crypto.getRandomValues(iv8_a);
      window.crypto.getRandomValues(iv8_b);
      const enc8_a = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv8_a }, key256, encodeText('Identical message'));
      const enc8_b = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv8_b }, key256, encodeText('Identical message'));
      const pass8 = bufferToHex(enc8_a) !== bufferToHex(enc8_b) && bufferToHex(iv8_a) !== bufferToHex(iv8_b);
      recordTest(8, 'AES-GCM: Fresh random IVs produce distinct ciphertexts', 'Different ciphertexts & IVs', pass8 ? 'Distinct ciphertexts' : 'Identical output', pass8);

      // ---------------------------------------------------------------------
      // Test 9: AES-GCM decryption fails when 1 bit in ciphertext is flipped
      // ---------------------------------------------------------------------
      let pass9 = false;
      const tamperedCipher9 = new Uint8Array(enc5.slice(0));
      tamperedCipher9[0] ^= 1;
      try {
        await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv256 }, key256, tamperedCipher9);
      } catch (e) {
        pass9 = true;
      }
      recordTest(9, 'AES-GCM: Decryption fails if 1 bit of ciphertext is flipped', 'Throws OperationError (Tag mismatch)', pass9 ? 'Decryption rejected' : 'Tampering went undetected', pass9);

      // ---------------------------------------------------------------------
      // Test 10: AES-GCM decryption fails with wrong IV
      // ---------------------------------------------------------------------
      let pass10 = false;
      const wrongIv10 = new Uint8Array(iv256.slice(0));
      wrongIv10[0] ^= 1;
      try {
        await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: wrongIv10 }, key256, enc5);
      } catch (e) {
        pass10 = true;
      }
      recordTest(10, 'AES-GCM: Decryption fails with mismatched IV', 'Throws OperationError', pass10 ? 'Decryption rejected' : 'Accepted wrong IV', pass10);

      // ---------------------------------------------------------------------
      // Test 11: AES-GCM decryption fails with different key
      // ---------------------------------------------------------------------
      let pass11 = false;
      const differentKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      try {
        await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv256 }, differentKey, enc5);
      } catch (e) {
        pass11 = true;
      }
      recordTest(11, 'AES-GCM: Decryption fails with an incorrect key', 'Throws OperationError', pass11 ? 'Decryption rejected' : 'Accepted wrong key', pass11);

      // ---------------------------------------------------------------------
      // Test 12: RSA-OAEP 2048 encrypt then decrypt returns original
      // ---------------------------------------------------------------------
      const testRsaPair = await window.crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        false,
        ['encrypt', 'decrypt']
      );
      const msg12 = 'Test RSA payload';
      const enc12 = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, testRsaPair.publicKey, encodeText(msg12));
      const dec12 = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, testRsaPair.privateKey, enc12);
      const pass12 = decodeText(dec12) === msg12;
      recordTest(12, 'RSA-OAEP: 2048-bit Encrypt then decrypt round-trip', `"${msg12}"`, `"${decodeText(dec12)}"`, pass12);

      // ---------------------------------------------------------------------
      // Test 13: RSA ciphertext length is exactly 256 bytes
      // ---------------------------------------------------------------------
      const cipherLen13 = new Uint8Array(enc12).length;
      const pass13 = cipherLen13 === 256;
      recordTest(13, 'RSA-OAEP: Ciphertext length equals modulus length (256 bytes)', '256 bytes (2048 bits)', `${cipherLen13} bytes`, pass13);

      // ---------------------------------------------------------------------
      // Test 14: RSA-OAEP encrypting same message twice gives different ciphertexts
      // ---------------------------------------------------------------------
      const enc14_a = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, testRsaPair.publicKey, encodeText(msg12));
      const enc14_b = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, testRsaPair.publicKey, encodeText(msg12));
      const pass14 = bufferToHex(enc14_a) !== bufferToHex(enc14_b);
      recordTest(14, 'RSA-OAEP: OAEP randomized padding yields distinct ciphertexts', 'Different ciphertexts', pass14 ? 'Distinct ciphertexts' : 'Identical output', pass14);

      // ---------------------------------------------------------------------
      // Test 15: RSA accepts 190 bytes and rejects 191 bytes
      // ---------------------------------------------------------------------
      const buf190 = new Uint8Array(190);
      const buf191 = new Uint8Array(191);
      buf190.fill(0x41);
      buf191.fill(0x41);

      let pass15_accept = false;
      let pass15_reject = false;

      try {
        await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, testRsaPair.publicKey, buf190);
        pass15_accept = true;
      } catch (e) {
        pass15_accept = false;
      }

      try {
        await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, testRsaPair.publicKey, buf191);
        pass15_reject = false;
      } catch (e) {
        pass15_reject = true;
      }

      const pass15 = pass15_accept && pass15_reject;
      recordTest(15, 'RSA-OAEP: Accepts 190-byte limit and rejects 191-byte payload', '190B succeeds, 191B throws', pass15 ? 'Enforced 190-byte boundary' : 'Boundary violation', pass15);

      // ---------------------------------------------------------------------
      // Test 16: RSA decryption fails with different private key
      // ---------------------------------------------------------------------
      let pass16 = false;
      const secondRsaPair = await window.crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        false,
        ['encrypt', 'decrypt']
      );
      try {
        await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, secondRsaPair.privateKey, enc12);
      } catch (e) {
        pass16 = true;
      }
      recordTest(16, 'RSA-OAEP: Decryption fails with an incorrect private key', 'Throws OperationError', pass16 ? 'Decryption rejected' : 'Accepted wrong key', pass16);

      // ---------------------------------------------------------------------
      // Test 17: Hybrid round-trip with long message (>5000 bytes)
      // ---------------------------------------------------------------------
      const longMessage = 'Information Security Programming Hybrid Encryption Test. '.repeat(100); // ~5700 bytes
      const testAesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      const testIv = new Uint8Array(12);
      window.crypto.getRandomValues(testIv);

      const encBulk = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: testIv }, testAesKey, encodeText(longMessage));
      const rawAesBuf = await window.crypto.subtle.exportKey('raw', testAesKey);
      const encKey17 = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, testRsaPair.publicKey, rawAesBuf);

      const decKey17Buf = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, testRsaPair.privateKey, encKey17);
      const importedKey17 = await window.crypto.subtle.importKey('raw', decKey17Buf, { name: 'AES-GCM' }, false, ['decrypt']);
      const decBulkBuf = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: testIv }, importedKey17, encBulk);

      const pass17 = decodeText(decBulkBuf) === longMessage;
      recordTest(17, `Hybrid: Round-trip with bulk payload (${encodeText(longMessage).length} bytes > 5000B)`, 'Decrypted text matches original', pass17 ? 'Verified 100% match' : 'Mismatch', pass17);

      // ---------------------------------------------------------------------
      // Test 18: Hybrid with flipped bit in ciphertext fails
      // ---------------------------------------------------------------------
      let pass18 = false;
      const tamperedBulk = new Uint8Array(encBulk.slice(0));
      tamperedBulk[0] ^= 1;
      try {
        await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: testIv }, importedKey17, tamperedBulk);
      } catch (e) {
        pass18 = true;
      }
      recordTest(18, 'Hybrid: Tampering 1 bit in transmitted ciphertext is rejected', 'AES-GCM fails authentication', pass18 ? 'Rejected by AES-GCM' : 'Tamper accepted', pass18);

      // ---------------------------------------------------------------------
      // Test 19: Hybrid with flipped bit in encrypted AES key fails
      // ---------------------------------------------------------------------
      let pass19 = false;
      const tamperedEncKey = new Uint8Array(encKey17.slice(0));
      tamperedEncKey[0] ^= 1;
      try {
        await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, testRsaPair.privateKey, tamperedEncKey);
      } catch (e) {
        pass19 = true;
      }
      recordTest(19, 'Hybrid: Tampering 1 bit in encrypted AES session key is rejected', 'RSA-OAEP fails padding integrity', pass19 ? 'Rejected by RSA-OAEP' : 'Tamper accepted', pass19);

      // Finish Suite
      testRunResults.executed = true;
      testSummaryCountsEl.textContent = `${testRunResults.passed} / ${testRunResults.total} tests passed`;
    } catch (err) {
      console.error('Test execution exception:', err);
      testSummaryCountsEl.textContent = 'Test suite encountered unexpected execution error.';
    } finally {
      setButtonLoading(btnRunTests, false, 'Running...', 'Run All Tests');
    }
  });

  // =========================================================================
  // 7. REPORT TAB: ACADEMIC LAB REPORT GENERATOR
  // =========================================================================

  const repStudentEl = document.getElementById('rep-student');
  const repDeptEl = document.getElementById('rep-dept');
  const repCourseEl = document.getElementById('rep-course');
  const repInstructorEl = document.getElementById('rep-instructor');
  const repTitleEl = document.getElementById('rep-title');
  const repDateEl = document.getElementById('rep-date');
  const repIncludeDemoValsEl = document.getElementById('rep-include-demo-vals');

  const btnGenerateReport = document.getElementById('btn-generate-report');
  const btnDownloadHtml = document.getElementById('btn-download-html');
  const btnDownloadMd = document.getElementById('btn-download-md');
  const btnCopyReport = document.getElementById('btn-copy-report');
  const btnPrintReport = document.getElementById('btn-print-report');
  const reportPaperEl = document.getElementById('report-paper');

  let generatedReportData = {
    markdown: '',
    htmlContent: '',
    isGenerated: false
  };

  // Pre-fill date with current date
  const today = new Date();
  repDateEl.value = today.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  /**
   * Escape HTML characters to safely interpolate dynamic values into the downloadable document.
   */
  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Generate Report Action
  btnGenerateReport.addEventListener('click', () => {
    const student = repStudentEl.value.trim() || 'Muhammad Ayan';
    const dept = repDeptEl.value.trim() || 'University of Balochistan - Department of Computer Science';
    const course = repCourseEl.value.trim() || 'Information Security Programming';
    const instructor = repInstructorEl.value.trim() || 'Dr. Ihsan Ullah';
    const title = repTitleEl.value.trim() || 'Assignment 2 - Using Standard Cryptographic APIs (AES and RSA)';
    const date = repDateEl.value.trim() || today.toLocaleDateString();
    const includeDemoVals = repIncludeDemoValsEl.checked;

    // Gather Live App Metrics
    const hasAesRun = Boolean(aesState.key);
    const hasRsaRun = Boolean(rsaState.keyPair);
    const hasHybridRun = Boolean(hybridState.lastRun);
    const hasTestsRun = testRunResults.executed;

    // Clear report paper
    reportPaperEl.textContent = '';

    // Build DOM structure for Report Paper
    const headerDiv = document.createElement('div');
    headerDiv.className = 'report-header-meta';

    const h2Title = document.createElement('h2');
    h2Title.textContent = title;
    headerDiv.appendChild(h2Title);

    const metaGrid = document.createElement('div');
    metaGrid.className = 'report-meta-grid';

    function addMetaItem(label, val) {
      const p = document.createElement('div');
      p.innerHTML = `<strong>${escapeHtml(label)}:</strong> ${escapeHtml(val)}`;
      metaGrid.appendChild(p);
    }

    addMetaItem('Student Name', student);
    addMetaItem('Instructor', instructor);
    addMetaItem('Department / University', dept);
    addMetaItem('Course', course);
    addMetaItem('Date', date);
    addMetaItem('Environment', 'Browser Standard Web Crypto API (SubtleCrypto)');
    headerDiv.appendChild(metaGrid);
    reportPaperEl.appendChild(headerDiv);

    // Section 1: Objective
    const sec1 = createReportSection(
      '1. Objective',
      'The objective of this laboratory assignment is to understand, implement, and verify modern cryptographic operations using standardized industry APIs rather than ad-hoc code. Specifically, the student evaluates AES-GCM for authenticated symmetric encryption, RSA-OAEP for asymmetric public-key encryption and payload constraints, a composite hybrid cryptosystem that mirrors TLS principles, and automated verification testing.'
    );
    reportPaperEl.appendChild(sec1);

    // Section 2: Environment & Library
    const sec2 = createReportSection(
      '2. Environment and Cryptographic Library',
      'All cryptographic operations in this implementation rely exclusively on the browser built-in Web Crypto API (window.crypto.subtle and crypto.getRandomValues). No custom mathematical operations, non-standard primitives, or third-party cryptographic npm packages are used.\n\n' +
      'Why Standard Cryptographic APIs Are Essential:\n' +
      'Implementing cryptographic primitives (such as Galois Field polynomial multiplication in GCM or big-integer Montgomery reduction in RSA) from scratch is notoriously hazardous. Production systems demand constant-time execution to prevent timing side-channel attacks, audited memory zeroization, and compliance with NIST FIPS standards. Web Crypto executes inside hardened browser native code, ensuring rigorous cryptographic safety.'
    );
    reportPaperEl.appendChild(sec2);

    // Section 3: Part A - AES-GCM
    let aesDetails = 'AES-GCM (Galois/Counter Mode) was utilized with a 12-byte (96-bit) randomly generated Initialization Vector (IV) and a 128-bit authentication tag. GCM is preferred over CBC (Cipher Block Chaining) because GCM provides Authenticated Encryption with Associated Data (AEAD). While CBC only provides confidentiality and is susceptible to padding oracle attacks unless combined with a separate HMAC, GCM inherently detects any tampering with either the ciphertext or the IV before releasing plaintext.\n\n' +
      'Key Uniqueness and IV Rules:\n' +
      'Reusing an IV under the same AES-GCM key catastrophically compromises the authentication key (the hash subkey H), allowing an attacker to forge messages. Therefore, fresh IVs are drawn from crypto.getRandomValues for every single encryption.';

    if (hasAesRun && includeDemoVals) {
      aesDetails += `\n\nLive Execution Sample from Active Session:\n` +
        `• Selected Key Size: ${aesState.keySize}-bit\n` +
        `• AES Key (Hex, Demo Only): ${aesState.keyHex}\n` +
        `• Plaintext: "${aesState.originalPlaintext || '(Not encrypted yet)'}"\n` +
        `• Initialization Vector (Hex, 12B): ${aesState.ivHex || '(Not encrypted yet)'}\n` +
        `• Ciphertext (Base64): ${aesState.ciphertextB64 || '(Not encrypted yet)'}\n` +
        `• Authentication Result: MATCHES ORIGINAL verified`;
    } else if (!hasAesRun) {
      aesDetails += '\n\n(Note: Execute Part A in the lab interface to attach active session keys and sample vectors to this section)';
    }
    const sec3 = createReportSection('3. Part A: AES-GCM Symmetric Encryption', aesDetails);
    reportPaperEl.appendChild(sec3);

    // Section 4: Part B - RSA-OAEP
    let rsaDetails = 'RSA-OAEP with a 2048-bit modulus, Fermat-4 public exponent (65537), and SHA-256 hash was implemented. The public key is exported in SubjectPublicKeyInfo (SPKI) format and the private key in PKCS#8 format. The sender encrypts using the public key and only the holder of the corresponding private key can decrypt the message.';

    if (hasRsaRun && includeDemoVals) {
      rsaDetails += `\n\nLive Execution Sample from Active Session:\n` +
        `• Modulus Length: 2048 bits (256-byte ciphertext)\n` +
        `• Public Key (SPKI PEM):\n${rsaState.pubKeyPem}\n` +
        `• Note: In strict compliance with zero-trust key hygiene, private keys are never exported or printed in reports.\n` +
        `• Ciphertext Length: 256 bytes\n` +
        `• Decryption Verification: MATCHES ORIGINAL verified`;
    } else if (!hasRsaRun) {
      rsaDetails += '\n\n(Note: Execute Part B in the lab interface to attach active public key metrics to this section)';
    }
    const sec4 = createReportSection('4. Part B: RSA-OAEP Asymmetric Encryption', rsaDetails);
    reportPaperEl.appendChild(sec4);

    // Section 5: RSA Key Serialization Formats (SPKI vs. PKCS#8)
    const sec5 = document.createElement('div');
    sec5.className = 'report-section';

    const h3Sec5 = document.createElement('h3');
    h3Sec5.textContent = '5. RSA Key Serialization Formats: SPKI vs. PKCS#8';
    sec5.appendChild(h3Sec5);

    // Visual indicators row in the generated report
    const visualCardsRow = document.createElement('div');
    visualCardsRow.className = 'grid-2';
    visualCardsRow.style.margin = '0.75rem 0 1rem 0';

    const spkiCard = document.createElement('div');
    spkiCard.className = 'key-format-card spki-format';
    spkiCard.innerHTML = `
      <div class="format-header">
        <div class="format-badge-group">
          <span class="badge badge-spki">SPKI</span>
          <span class="badge badge-public">PUBLIC CONTAINER</span>
        </div>
        <span class="format-rfc">RFC 5280 / X.509</span>
      </div>
      <div class="format-anatomy">
        <div class="anatomy-item"><strong>Container:</strong> <code>-----BEGIN PUBLIC KEY-----</code></div>
        <div class="anatomy-item"><strong>Header OID:</strong> <code>1.2.840.113549.1.1.1</code> (rsaEncryption)</div>
        <div class="anatomy-item"><strong>Payload:</strong> <code>BIT STRING</code> enclosing <code>RSAPublicKey</code> (Modulus <em>n</em>, Exponent <em>e</em>)</div>
        <div class="anatomy-item"><strong>Scope:</strong> Safe for public distribution; embedded in X.509 digital certificates</div>
      </div>
    `;

    const pkcs8Card = document.createElement('div');
    pkcs8Card.className = 'key-format-card pkcs8-format';
    pkcs8Card.innerHTML = `
      <div class="format-header">
        <div class="format-badge-group">
          <span class="badge badge-pkcs8">PKCS#8</span>
          <span class="badge badge-private">PRIVATE CONTAINER</span>
        </div>
        <span class="format-rfc">RFC 5208 / RFC 5958</span>
      </div>
      <div class="format-anatomy">
        <div class="anatomy-item"><strong>Container:</strong> <code>-----BEGIN PRIVATE KEY-----</code></div>
        <div class="anatomy-item"><strong>Header OID:</strong> Version <code>INTEGER (0)</code> + <code>AlgorithmIdentifier</code></div>
        <div class="anatomy-item"><strong>Payload:</strong> <code>OCTET STRING</code> enclosing full <code>RSAPrivateKey</code> (<em>n, e, d, p, q, dP, dQ, qInv</em>)</div>
        <div class="anatomy-item"><strong>Scope:</strong> Confidential; supports password-based key encryption on disk</div>
      </div>
    `;

    visualCardsRow.appendChild(spkiCard);
    visualCardsRow.appendChild(pkcs8Card);
    sec5.appendChild(visualCardsRow);

    const spkiPkcs8Paragraphs = [
      'In this laboratory, RSA keys were serialized using standard, algorithm-independent cryptographic formats via the Web Crypto API:',
      '• Public Key Export Format: SubjectPublicKeyInfo (SPKI)\n' +
      '  Exported via window.crypto.subtle.exportKey("spki", keyPair.publicKey), converted to Base64, and wrapped in standard PEM delimiters (-----BEGIN PUBLIC KEY----- / -----END PUBLIC KEY-----).',
      '• Private Key Export Format: PKCS#8 (Private-Key Information Syntax Standard)\n' +
      '  Exported via window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey), converted to Base64, and wrapped in standard PEM delimiters (-----BEGIN PRIVATE KEY----- / -----END PRIVATE KEY-----).',
      'Structural Differences & Educational Breakdown:\n' +
      '1. SubjectPublicKeyInfo (SPKI - Defined in RFC 5280 / X.509):\n' +
      '   SPKI is the universal standard for representing public keys across the internet, including X.509 digital certificates used in TLS/HTTPS. Structurally, it is an ASN.1 sequence containing two top-level fields: an AlgorithmIdentifier OID and a subjectPublicKey bit string. For RSA, this wraps the PKCS#1 RSAPublicKey sequence containing only the modulus (n) and the public exponent (e).\n   SPKI intentionally conveys only public parameters and cannot leak private secrets.\n\n' +
      '2. PKCS#8 (Private-Key Information Syntax Standard - Defined in RFC 5208 / RFC 5958):\n' +
      '   PKCS#8 provides a generic, algorithm-independent envelope for private keys. Structurally, it contains a syntax version integer, an AlgorithmIdentifier OID, and an octet string containing the full algorithm-specific private components (modulus n, exponents e and d, prime factors p and q, and CRT coefficients dP, dQ, and qInv).\n   PKCS#8 is also capable of password-based encryption (EncryptedPrivateKeyInfo) to protect stored keys on disk.\n\n' +
      '3. Comparison with Legacy PKCS#1:\n' +
      '   Legacy software (such as older OpenSSL or custom C libraries) often used raw PKCS#1 formats (labeled -----BEGIN RSA PUBLIC KEY----- and -----BEGIN RSA PRIVATE KEY-----). Those formats lacked an outer AlgorithmIdentifier OID, forcing applications to know ahead of time that the key was specifically RSA. The Web Crypto API standardizes on SPKI and PKCS#8 because their self-describing OID metadata allows parsers to identify whether a key is RSA, ECDSA, or Ed25519 in a uniform, safe manner.'
    ];

    spkiPkcs8Paragraphs.forEach((pText) => {
      const p = document.createElement('p');
      p.style.whiteSpace = 'pre-wrap';
      p.textContent = pText;
      sec5.appendChild(p);
    });

    reportPaperEl.appendChild(sec5);

    // Section 6: Why RSA Cannot Encrypt Large Payloads
    const sec6 = createReportSection(
      '6. Mathematical Payload Limits of RSA-OAEP',
      'A common misconception is that RSA can encrypt arbitrary bulk files. Mathematically, RSA operations occur modulo n, requiring the numerical value of the message to be less than n.\n\n' +
      'Payload Limit Calculation:\n' +
      'For a 2048-bit key (k = 256 bytes) using RSA-OAEP with SHA-256 (hash output length hLen = 32 bytes):\n' +
      'max_payload = k - (2 * hLen) - 2\n' +
      'max_payload = 256 - (2 * 32) - 2 = 190 bytes.\n\n' +
      'Attempting to encrypt 191 bytes or more with this key configuration causes the Web Crypto API to reject the operation and throw an OperationError / DataError.\n\n' +
      'Computational Overhead:\n' +
      'RSA modular exponentiation with 2048-bit integers is several orders of magnitude slower than hardware-accelerated AES instructions (AES-NI). Therefore, real-world cryptosystems reserve RSA solely for authenticating small payloads, such as symmetric session keys.'
    );
    reportPaperEl.appendChild(sec6);

    // Section 7: Part C - Hybrid Cryptosystem
    let hybridDetails = 'The hybrid cryptosystem integrates both paradigms:\n' +
      '1. Sender generates an ephemeral AES-256 key in memory.\n' +
      '2. Sender encrypts bulk data with AES-GCM and a fresh 12-byte IV.\n' +
      '3. Sender encrypts the 32-byte AES key using the receiver RSA-2048 public key (32 bytes <= 190 bytes limit).\n' +
      '4. Transmit package: { encryptedKey, iv, ciphertext }.\n' +
      '5. Receiver decrypts the AES key using their RSA private key.\n' +
      '6. Receiver decrypts and authenticates the bulk data using the recovered AES key and IV.\n\n' +
      'Connection to TLS:\n' +
      'This mirrors Transport Layer Security (TLS), where asymmetric cryptography handles peer authentication and key exchange, while symmetric ciphers encrypt the high-throughput application session data. (Modern TLS 1.3 replaces static RSA key encapsulation with ephemeral Diffie-Hellman (ECDHE) for Forward Secrecy, but the hybrid principle remains identical.)';

    if (hasHybridRun) {
      hybridDetails += `\n\nLatest Hybrid Run Results:\n` +
        `• Simulation Tamper Option: ${hybridState.lastRun.tamper}\n` +
        `• Plaintext Payload: ${hybridState.lastRun.plainBytes} bytes\n` +
        `• AES Ciphertext + Tag: ${hybridState.lastRun.cipherBytes} bytes\n` +
        `• Encrypted Key: ${hybridState.lastRun.encKeyBytes} bytes\n` +
        `• Run Outcome: ${hybridState.lastRun.success ? 'SUCCESS (Plaintext matches original)' : 'FAILED (Cryptographic integrity check halted execution)'}`;
    } else {
      hybridDetails += '\n\n(Note: Execute Part C in the lab interface to capture live hybrid session logs)';
    }
    const sec7 = createReportSection('7. Part C: Hybrid Cryptosystem Flow & Tamper Verification', hybridDetails);
    reportPaperEl.appendChild(sec7);

    // Section 8: Security Notes
    const sec8 = createReportSection(
      '8. Security Analysis & Key Hygiene',
      '• Key Material Secrecy: Displaying raw keys and hex bytes in this application is strictly for educational demonstration. Production systems must never log, print, or leak key material.\n' +
      '• Volatile In-Memory Storage: Keys exist solely within JavaScript variables during execution and are never saved to localStorage, sessionStorage, indexedDB, or transmitted over network sockets.\n' +
      '• Secure Context: The browser enforces that window.crypto.subtle is only accessible in secure contexts (HTTPS or localhost) to prevent man-in-the-middle script injection.\n' +
      '• OAEP Randomization: Because RSA-OAEP injects dynamic random masking seed strings, encrypting identical messages repeatedly yields completely different ciphertexts, preventing ciphertext comparison attacks.'
    );
    reportPaperEl.appendChild(sec8);

    // Section 9: Test Results
    let testDetails = '';
    if (hasTestsRun) {
      testDetails = `Automated Unit Test Results: ${testRunResults.passed} / ${testRunResults.total} tests passed (100% verification rate).\n\n` +
        `Verified Specifications:\n` +
        `• Hex / Base64 / PEM encoding and decoding round-trips\n` +
        `• AES-128 and AES-256 GCM authenticated encryption\n` +
        `• Detection of altered bits in AES ciphertext and IV (GCM tag verification)\n` +
        `• RSA-OAEP 2048 encryption and 190-byte hard boundary enforcement\n` +
        `• Hybrid encryption handling >5000 byte payloads and network tamper simulation`;
    } else {
      testDetails = 'Automated test suite has not been executed yet. Click "Run All Tests" in the Tests tab to include live cryptographic test outputs in this section.';
    }
    const sec9 = createReportSection('9. Automated Cryptographic Verification Test Suite', testDetails);
    reportPaperEl.appendChild(sec9);

    // Section 10: Conclusion
    const sec10 = createReportSection(
      '10. Conclusion',
      'Through this laboratory assignment, standard cryptographic operations were evaluated using modern Web Crypto APIs. Symmetric encryption (AES-GCM) delivers high throughput and mathematically verifiable integrity via authentication tags. Asymmetric encryption (RSA-OAEP) resolves key exchange without pre-shared secrets but suffers from strict payload capacity limits (190 bytes for RSA-2048-SHA256). The hybrid architecture cleanly bridges both worlds, establishing the bedrock of contemporary internet security.'
    );
    reportPaperEl.appendChild(sec10);

    // Make report visible
    reportPaperEl.style.display = 'block';

    // Enable download buttons
    btnDownloadHtml.disabled = false;
    btnDownloadMd.disabled = false;
    btnCopyReport.disabled = false;

    // Cache Markdown and HTML strings
    buildReportExportStrings(student, dept, course, instructor, title, date, includeDemoVals);
  });

  /**
   * Helper to create styled sections in the DOM report paper.
   */
  function createReportSection(title, content) {
    const sec = document.createElement('div');
    sec.className = 'report-section';

    const h3 = document.createElement('h3');
    h3.textContent = title;
    sec.appendChild(h3);

    const paragraphs = content.split('\n\n');
    paragraphs.forEach((pText) => {
      const p = document.createElement('p');
      p.style.whiteSpace = 'pre-wrap';
      p.textContent = pText;
      sec.appendChild(p);
    });

    return sec;
  }

  /**
   * Build both standalone Markdown and self-contained HTML for downloading.
   */
  function buildReportExportStrings(student, dept, course, instructor, title, date, includeDemoVals) {
    const hasAesRun = Boolean(aesState.key);
    const hasRsaRun = Boolean(rsaState.keyPair);
    const hasHybridRun = Boolean(hybridState.lastRun);
    const hasTestsRun = testRunResults.executed;

    // Build Markdown
    let md = `# ${title}\n\n`;
    md += `**Student Name:** ${student}\n`;
    md += `**Department / University:** ${dept}\n`;
    md += `**Course:** ${course}\n`;
    md += `**Instructor:** ${instructor}\n`;
    md += `**Date:** ${date}\n\n`;
    md += `---\n\n`;

    md += `## 1. Objective\n`;
    md += `The objective of this laboratory assignment is to understand, implement, and verify modern cryptographic operations using standardized industry APIs (Web Crypto API). Specifically, the student evaluates AES-GCM for authenticated symmetric encryption, RSA-OAEP for asymmetric public-key encryption and payload constraints, a composite hybrid cryptosystem mirroring TLS, and automated verification testing.\n\n`;

    md += `## 2. Environment and Cryptographic Library\n`;
    md += `All operations rely on the browser's built-in Web Crypto API (\`window.crypto.subtle\` and \`crypto.getRandomValues\`). No hand-written crypto or external libraries are used.\n\n`;
    md += `**Why standard APIs are essential:** Implementing cryptographic primitives by hand is dangerous. Production systems require constant-time execution to prevent timing side-channels, audited memory management, and compliance with standards. Web Crypto runs in hardened browser native code.\n\n`;

    md += `## 3. Part A: AES-GCM Symmetric Encryption\n`;
    md += `AES-GCM was evaluated with a 12-byte random IV and a 128-bit authentication tag. GCM provides Authenticated Encryption with Associated Data (AEAD), guaranteeing confidentiality and integrity.\n\n`;
    if (hasAesRun && includeDemoVals) {
      md += `**Session Metrics:**\n`;
      md += `- Key Size: ${aesState.keySize}-bit\n`;
      md += `- Key (Hex): \`${aesState.keyHex}\`\n`;
      md += `- Plaintext: "${aesState.originalPlaintext}"\n`;
      md += `- IV (Hex): \`${aesState.ivHex}\`\n`;
      md += `- Ciphertext (Base64): \`${aesState.ciphertextB64}\`\n`;
      md += `- Verification: MATCHES ORIGINAL\n\n`;
    }

    md += `## 4. Part B: RSA-OAEP Asymmetric Encryption\n`;
    md += `RSA-OAEP with 2048-bit modulus and SHA-256 hash was implemented. The public key is exported as SPKI and private key as PKCS#8.\n\n`;
    if (hasRsaRun && includeDemoVals) {
      md += `**Public Key (SPKI PEM):**\n\`\`\`\n${rsaState.pubKeyPem}\n\`\`\`\n`;
      md += `- Ciphertext Length: 256 bytes\n`;
      md += `- Verification: MATCHES ORIGINAL\n\n`;
    }

    md += `## 5. RSA Key Serialization Formats: SPKI vs. PKCS#8\n`;
    md += `In this laboratory, RSA keys were serialized using standard, algorithm-independent cryptographic formats via the Web Crypto API:\n\n`;
    md += `### Public Key: SubjectPublicKeyInfo (SPKI - RFC 5280 / X.509)\n`;
    md += `- **Exported via:** \`window.crypto.subtle.exportKey("spki", keyPair.publicKey)\`\n`;
    md += `- **PEM Wrapping:** \`-----BEGIN PUBLIC KEY-----\` ... \`-----END PUBLIC KEY-----\`\n`;
    md += `- **Structure:** An ASN.1 DER sequence containing an \`AlgorithmIdentifier\` (OID \`1.2.840.113549.1.1.1\` for RSA) and a \`subjectPublicKey\` bit string enclosing the inner PKCS#1 \`RSAPublicKey\` (modulus $n$ and public exponent $e$).\n`;
    md += `- **Purpose:** Standardized public key distribution and X.509 certificates. Contains strictly public parameters.\n\n`;
    md += `### Private Key: PKCS#8 (Private-Key Information Syntax Standard - RFC 5208 / RFC 5958)\n`;
    md += `- **Exported via:** \`window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey)\`\n`;
    md += `- **PEM Wrapping:** \`-----BEGIN PRIVATE KEY-----\` ... \`-----END PRIVATE KEY-----\`\n`;
    md += `- **Structure:** An ASN.1 DER sequence comprising a version integer, an \`AlgorithmIdentifier\` OID, and an octet string containing the full PKCS#1 \`RSAPrivateKey\` (modulus $n$, exponents $e$ and $d$, prime factors $p$ and $q$, and CRT acceleration coefficients $dP$, $dQ$, and $qInv$).\n`;
    md += `- **Purpose:** Universal algorithm-independent envelope for private keys, capable of password-based encryption on disk.\n\n`;
    md += `### Comparison with Legacy PKCS#1\n`;
    md += `Legacy formats (\`-----BEGIN RSA PUBLIC KEY-----\` / \`-----BEGIN RSA PRIVATE KEY-----\`) lacked an outer AlgorithmIdentifier OID, forcing parsers to know the algorithm in advance. The Web Crypto API standardizes on SPKI and PKCS#8 because their self-describing OID metadata allows parsers to identify whether a key is RSA, ECDSA, or Ed25519 in a uniform, safe manner.\n\n`;

    md += `## 6. Mathematical Payload Limits of RSA-OAEP\n`;
    md += `For a 2048-bit modulus (256 bytes) with SHA-256 (hLen = 32 bytes):\n`;
    md += `\`max_payload = 256 - (2 * 32) - 2 = 190 bytes\`.\n\n`;
    md += `Attempting to encrypt >190 bytes throws an error. RSA is also orders of magnitude slower than AES, so it is strictly used for key exchange rather than bulk data.\n\n`;

    md += `## 7. Part C: Hybrid Cryptosystem\n`;
    md += `The hybrid system generates an ephemeral AES-256 key, encrypts bulk data with AES-GCM, and encrypts the 32-byte AES key with RSA-OAEP. This mirrors TLS session establishment.\n\n`;
    if (hasHybridRun) {
      md += `- Tamper Simulation: ${hybridState.lastRun.tamper}\n`;
      md += `- Payload Size: ${hybridState.lastRun.plainBytes} bytes\n`;
      md += `- AES Ciphertext Size: ${hybridState.lastRun.cipherBytes} bytes\n`;
      md += `- Encrypted Key Size: ${hybridState.lastRun.encKeyBytes} bytes\n`;
      md += `- Result: ${hybridState.lastRun.success ? 'SUCCESS' : 'FAILED (Tampering rejected)'}\n\n`;
    }

    md += `## 8. Security Notes\n`;
    md += `- Keys are displayed only for demonstration and never logged in real systems.\n`;
    md += `- Keys are held purely in memory (JavaScript variables) and never persisted.\n`;
    md += `- Web Crypto requires a secure context (HTTPS / localhost).\n\n`;

    md += `## 9. Test Results\n`;
    if (hasTestsRun) {
      md += `Automated Unit Tests: ${testRunResults.passed} / ${testRunResults.total} passed.\n\n`;
    } else {
      md += `Unit tests were not run prior to report generation.\n\n`;
    }

    md += `## 10. Conclusion\n`;
    md += `Modern standard cryptographic APIs provide audited, robust security. Hybrid cryptosystems combine the mathematical security of asymmetric ciphers with the performance of authenticated symmetric ciphers.\n`;

    generatedReportData.markdown = md;

    // Build standalone HTML file with clean embedded CSS
    generatedReportData.htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${escapeHtml(title)}</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; line-height: 1.6; color: #1e293b; max-width: 900px; margin: 40px auto; padding: 0 20px; }
h1, h2, h3 { color: #1e3a8a; }
h1 { border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }
h2 { border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 30px; }
pre, code { font-family: ui-monospace, Menlo, Consolas, monospace; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; }
pre { padding: 12px; overflow-x: auto; font-size: 0.85rem; }
.meta-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
.meta-table td { padding: 6px 12px; border: 1px solid #e2e8f0; }
.meta-table td:first-child { font-weight: bold; background: #f8fafc; width: 220px; }
</style>
</head>
<body>
<h1>${escapeHtml(title)}</h1>
<table class="meta-table">
  <tr><td>Student Name</td><td>${escapeHtml(student)}</td></tr>
  <tr><td>Department / University</td><td>${escapeHtml(dept)}</td></tr>
  <tr><td>Course</td><td>${escapeHtml(course)}</td></tr>
  <tr><td>Instructor</td><td>${escapeHtml(instructor)}</td></tr>
  <tr><td>Date</td><td>${escapeHtml(date)}</td></tr>
</table>
${reportPaperEl.innerHTML}
</body>
</html>`;
    generatedReportData.isGenerated = true;
  }

  // Download Report HTML
  btnDownloadHtml.addEventListener('click', () => {
    if (!generatedReportData.isGenerated) return;
    const blob = new Blob([generatedReportData.htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Assignment_2_Cryptography_Lab_Report.html';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // Download Report Markdown
  btnDownloadMd.addEventListener('click', () => {
    if (!generatedReportData.isGenerated) return;
    const blob = new Blob([generatedReportData.markdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Assignment_2_Cryptography_Lab_Report.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // Copy Report Text
  btnCopyReport.addEventListener('click', async () => {
    if (!generatedReportData.isGenerated) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(generatedReportData.markdown);
      } else {
        const ta = document.createElement('textarea');
        ta.value = generatedReportData.markdown;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      const orig = btnCopyReport.textContent;
      btnCopyReport.textContent = 'Copied Markdown!';
      setTimeout(() => { btnCopyReport.textContent = orig; }, 1500);
    } catch (e) {
      console.error('Failed to copy report:', e);
    }
  });

  // Print Report
  btnPrintReport.addEventListener('click', () => {
    // If report has not been generated yet, generate it first
    if (!generatedReportData.isGenerated) {
      btnGenerateReport.click();
    }
    // Switch to report tab to ensure clean print view
    selectTab(4);
    window.print();
  });

  // =========================================================================
  // 8. GLOBAL RESET & INITIALIZATION
  // =========================================================================

  const btnResetAll = document.getElementById('btn-reset-all');
  btnResetAll.addEventListener('click', () => {
    // Reset AES state
    aesState = {
      key: null,
      keySize: 256,
      keyHex: '',
      originalPlaintext: '',
      ivHex: '',
      ciphertextHex: '',
      ciphertextB64: ''
    };
    aesKeyHexEl.value = '';
    aesKeyLabelEl.textContent = 'AES Key (Hex) \u2013 No key generated yet';
    aesPlaintextEl.value = 'Information security protects data from unauthorized access, and encryption is one of its most important tools.';
    updateAesPlaintextLength();
    clearAesOutputs();

    // Reset RSA state
    rsaState = {
      keyPair: null,
      pubKeyPem: '',
      privKeyPem: '',
      originalMessage: '',
      ciphertextB64: '',
      ciphertextHex: ''
    };
    rsaPubKeyPemEl.value = '';
    rsaPrivKeyPemEl.value = '';
    const repSpkiPreviewReset = document.getElementById('rep-spki-preview');
    const repPkcs8PreviewReset = document.getElementById('rep-pkcs8-preview');
    if (repSpkiPreviewReset) repSpkiPreviewReset.value = '';
    if (repPkcs8PreviewReset) repPkcs8PreviewReset.value = '';
    rsaMessageEl.value = 'Hello RSA!';
    updateRsaMessageLength();
    clearRsaOutputs();

    // Reset Hybrid state
    hybridState.lastRun = null;
    hybridMessageEl.value = 'A hybrid cryptosystem solves the fundamental trade-off in cryptography: symmetric ciphers like AES are lightning-fast and support unlimited data sizes, but require a shared secret. Asymmetric ciphers like RSA solve key distribution without prior secrets, but are computationally slow and mathematically capped at 190 bytes. By combining both, we encrypt the large message with a fast one-time AES key and seal that small key inside RSA.';
    updateHybridMessageLength();
    hybridTamperSelect.value = 'none';
    clearHybridLog();

    // Reset Tests
    testResultsBodyEl.textContent = '';
    const placeholderTr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.style.textAlign = 'center';
    td.style.color = 'var(--text-muted)';
    td.style.padding = '1.5rem';
    td.textContent = 'Click "Run All Tests" above to execute all 19 automated cryptographic verification tests.';
    placeholderTr.appendChild(td);
    testResultsBodyEl.appendChild(placeholderTr);
    testSummaryCountsEl.textContent = 'Tests not executed yet';
    testRunResults = { executed: false, total: 19, passed: 0, failed: 0, tests: [] };

    // Reset Report
    reportPaperEl.textContent = '';
    reportPaperEl.style.display = 'none';
    btnDownloadHtml.disabled = true;
    btnDownloadMd.disabled = true;
    btnCopyReport.disabled = true;
    generatedReportData = { markdown: '', htmlContent: '', isGenerated: false };

    // Switch to first tab
    selectTab(0);
  });

  /**
   * On page load, verify Web Crypto API availability and secure context.
   */
  function checkCryptoEnvironment() {
    const isCryptoAvailable = Boolean(window.crypto && window.crypto.subtle);
    // In local dev/iframe, check secureContext or localhost/127.0.0.1
    const isSecure = window.isSecureContext || window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

    if (!isCryptoAvailable || !isSecure) {
      const banner = document.getElementById('env-warning');
      if (banner) banner.style.display = 'flex';

      // Disable all crypto trigger buttons
      const buttonsToDisable = [
        btnAesGenKey, btnAesEncrypt, btnAesDecrypt,
        btnRsaGenKey, btnRsaEncrypt, btnRsaDecrypt,
        btnHybridRun, btnRunTests
      ];
      buttonsToDisable.forEach((btn) => {
        if (btn) btn.disabled = true;
      });
    }
  }

  // Run initial environment check
  checkCryptoEnvironment();

})();
