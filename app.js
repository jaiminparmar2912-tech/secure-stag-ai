/**
 * StegoShield - Secure Client-Side Image Steganography Engine
 * Features:
 *  - Web Cryptography API (AES-256-GCM + PBKDF2 with SHA-256)
 *  - 100,000 PBKDF2 Iterations with 16-byte random salt
 *  - LSB (Least Significant Bit) Pixel Plane Embedding
 *  - Tamper detection via GCM authenticated cipher tags
 *  - Pure Vanilla JavaScript, zero external dependencies
 */

(function () {
  'use strict';

  // Constants
  const MAGIC_HEADER = new Uint8Array([0x53, 0x54, 0x45, 0x47]); // "STEG"
  const FLAG_ENCRYPTED = 0x01;
  const FLAG_PLAINTEXT = 0x00;
  const SALT_LENGTH = 16;
  const IV_LENGTH = 12;
  const HEADER_SIZE = 9; // 4 magic + 1 flag + 4 length

  // Application State
  const state = {
    encodeImage: null,
    encodeImageDimensions: { width: 0, height: 0 },
    encodeCapacityBytes: 0,
    decodeImage: null,
    decodeImageDimensions: { width: 0, height: 0 },
    activeBlobUrl: null
  };

  // DOM Elements
  const DOM = {
    // Tabs
    tabBtns: document.querySelectorAll('.tab-btn'),
    panelSections: document.querySelectorAll('.panel-section'),

    // Encode Elements
    encodeDropzone: document.getElementById('encode-dropzone'),
    encodeFileInput: document.getElementById('encode-file-input'),
    encodeDropContent: document.getElementById('encode-drop-content'),
    encodePreviewWrapper: document.getElementById('encode-preview-wrapper'),
    encodePreviewImg: document.getElementById('encode-preview-img'),
    encodeRemoveImg: document.getElementById('encode-remove-img'),
    encodeImgInfo: document.getElementById('encode-img-info'),
    capacityBox: document.getElementById('capacity-box'),
    capacityText: document.getElementById('capacity-text'),
    capacityBar: document.getElementById('capacity-bar'),
    secretMessage: document.getElementById('secret-message'),
    secretCharCount: document.getElementById('secret-char-count'),
    enableEncryption: document.getElementById('enable-encryption'),
    encodePasswordWrapper: document.getElementById('encode-password-wrapper'),
    encodePassword: document.getElementById('encode-password'),
    encodeTogglePw: document.getElementById('encode-toggle-pw'),
    strengthBar: document.getElementById('strength-bar'),
    strengthText: document.getElementById('strength-text'),
    btnEncode: document.getElementById('btn-encode'),
    encodeResultPlaceholder: document.getElementById('encode-result-placeholder'),
    encodeResultActive: document.getElementById('encode-result-active'),
    encodeResultImg: document.getElementById('encode-result-img'),
    btnDownloadStego: document.getElementById('btn-download-stego'),
    resMetaSize: document.getElementById('res-meta-size'),
    resMetaEnc: document.getElementById('res-meta-enc'),
    resMetaPixels: document.getElementById('res-meta-pixels'),

    // Decode Elements
    decodeDropzone: document.getElementById('decode-dropzone'),
    decodeFileInput: document.getElementById('decode-file-input'),
    decodeDropContent: document.getElementById('decode-drop-content'),
    decodePreviewWrapper: document.getElementById('decode-preview-wrapper'),
    decodePreviewImg: document.getElementById('decode-preview-img'),
    decodeRemoveImg: document.getElementById('decode-remove-img'),
    decodeImgInfo: document.getElementById('decode-img-info'),
    decodePassword: document.getElementById('decode-password'),
    decodeTogglePw: document.getElementById('decode-toggle-pw'),
    btnDecode: document.getElementById('btn-decode'),
    decodeResultPlaceholder: document.getElementById('decode-result-placeholder'),
    decodeResultActive: document.getElementById('decode-result-active'),
    extractedTextArea: document.getElementById('extracted-text-area'),
    btnCopyExtracted: document.getElementById('btn-copy-extracted'),
    decodeStatusChip: document.getElementById('decode-status-chip'),
    decodeChipText: document.getElementById('decode-chip-text'),
    decodePayloadLength: document.getElementById('decode-payload-length'),
    decodeMetaCipher: document.getElementById('decode-meta-cipher'),
    decodeMetaIntegrity: document.getElementById('decode-meta-integrity'),

    // Global
    toastContainer: document.getElementById('toast-container'),
    hiddenCanvas: document.getElementById('hidden-canvas')
  };

  /* =========================================================================
     CRYPTOGRAPHY ENGINE (Web Crypto API: AES-256-GCM + PBKDF2)
     ========================================================================= */

  /**
   * Derives a 256-bit AES-GCM key from a password and salt using PBKDF2-SHA256.
   */
  async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypts plaintext string using AES-256-GCM.
   */
  async function encryptPayload(plainText, password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const key = await deriveKey(password, salt);
    const enc = new TextEncoder();

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      enc.encode(plainText)
    );

    return {
      salt,
      iv,
      ciphertext: new Uint8Array(ciphertextBuffer)
    };
  }

  /**
   * Decrypts ciphertext Uint8Array using AES-256-GCM and verifies authenticity.
   */
  async function decryptPayload(ciphertext, password, salt, iv) {
    const key = await deriveKey(password, salt);
    try {
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ciphertext
      );
      const dec = new TextDecoder();
      return dec.decode(decryptedBuffer);
    } catch (err) {
      throw new Error('Authentication failed: Incorrect password or corrupted payload.');
    }
  }

  /* =========================================================================
     STEGANOGRAPHY ENGINE (LSB Encoding & Extraction)
     ========================================================================= */

  /**
   * Packs header and payload into a single binary Uint8Array.
   */
  function buildStegoPacket(flag, length, salt, iv, bodyBytes) {
    const totalSize = HEADER_SIZE + (flag === FLAG_ENCRYPTED ? (SALT_LENGTH + IV_LENGTH) : 0) + bodyBytes.length;
    const packet = new Uint8Array(totalSize);

    // 1. Magic bytes "STEG"
    packet.set(MAGIC_HEADER, 0);

    // 2. Encryption Flag
    packet[4] = flag;

    // 3. Payload length (32-bit Big Endian)
    const lenView = new DataView(packet.buffer, 5, 4);
    lenView.setUint32(0, length, false);

    let offset = 9;

    // 4. Salt and IV if encrypted
    if (flag === FLAG_ENCRYPTED) {
      packet.set(salt, offset);
      offset += SALT_LENGTH;
      packet.set(iv, offset);
      offset += IV_LENGTH;
    }

    // 5. Body (Ciphertext or Plaintext)
    packet.set(bodyBytes, offset);

    return packet;
  }

  /**
   * Embeds binary packet into the Least Significant Bits of the image's RGB channels.
   * Alpha (channel 4) is untouched to preserve opacity and avoid browser premultiplication.
   */
  function embedPacketInImageData(imageData, packet) {
    const data = imageData.data;
    const totalBits = packet.length * 8;
    const maxCapacityBits = (imageData.width * imageData.height) * 3;

    if (totalBits > maxCapacityBits) {
      throw new Error(`Data size (${packet.length} bytes) exceeds image capacity (${Math.floor(maxCapacityBits / 8)} bytes).`);
    }

    let byteIdx = 0;
    let bitIdx = 7;
    let bitsWritten = 0;

    for (let i = 0; i < data.length; i += 4) {
      // Loop through RGB channels (i+0, i+1, i+2)
      for (let c = 0; c < 3; c++) {
        if (bitsWritten >= totalBits) return;

        const currentByte = packet[byteIdx];
        const bit = (currentByte >> bitIdx) & 1;

        // Replace LSB
        data[i + c] = (data[i + c] & 0xFE) | bit;

        bitIdx--;
        if (bitIdx < 0) {
          bitIdx = 7;
          byteIdx++;
        }
        bitsWritten++;
      }
    }
  }

  /**
   * Extracts specified number of bytes from the image starting at a bit offset.
   */
  function extractBytesFromImageData(imageData, startBitOffset, byteCount) {
    const data = imageData.data;
    const result = new Uint8Array(byteCount);
    let currentBitPos = 0;
    let targetByteIdx = 0;
    let targetBitIdx = 7;
    let currentAccumulator = 0;

    for (let i = 0; i < data.length; i += 4) {
      for (let c = 0; c < 3; c++) {
        if (currentBitPos >= startBitOffset) {
          const bit = data[i + c] & 1;
          currentAccumulator = (currentAccumulator << 1) | bit;
          targetBitIdx--;

          if (targetBitIdx < 0) {
            result[targetByteIdx] = currentAccumulator;
            targetByteIdx++;
            currentAccumulator = 0;
            targetBitIdx = 7;

            if (targetByteIdx >= byteCount) {
              return result;
            }
          }
        }
        currentBitPos++;
      }
    }

    return result;
  }

  /**
   * Scans image for StegoShield signature and extracts concealed payload.
   */
  async function extractStegoPayload(imageData, password) {
    const maxCapacityBits = (imageData.width * imageData.height) * 3;
    const maxCapacityBytes = Math.floor(maxCapacityBits / 8);

    if (maxCapacityBytes < HEADER_SIZE) {
      throw new Error('Image is too small to contain a StegoShield payload.');
    }

    // 1. Read the 9-byte header (bits 0 to 71)
    const headerBytes = extractBytesFromImageData(imageData, 0, HEADER_SIZE);

    // Verify Magic bytes "STEG"
    for (let i = 0; i < 4; i++) {
      if (headerBytes[i] !== MAGIC_HEADER[i]) {
        throw new Error('No StegoShield hidden message detected in this image. (Missing magic signature)');
      }
    }

    const flag = headerBytes[4];
    const lenView = new DataView(headerBytes.buffer, 5, 4);
    const bodyLength = lenView.getUint32(0, false);

    if (bodyLength <= 0 || bodyLength > maxCapacityBytes) {
      throw new Error('Corrupted or invalid payload length detected in carrier.');
    }

    let startBit = HEADER_SIZE * 8;

    if (flag === FLAG_ENCRYPTED) {
      if (!password || password.trim() === '') {
        throw new Error('This image contains an encrypted message. Please enter the decryption password.');
      }

      // Read Salt (16 bytes)
      const salt = extractBytesFromImageData(imageData, startBit, SALT_LENGTH);
      startBit += SALT_LENGTH * 8;

      // Read IV (12 bytes)
      const iv = extractBytesFromImageData(imageData, startBit, IV_LENGTH);
      startBit += IV_LENGTH * 8;

      // Read Ciphertext
      const ciphertext = extractBytesFromImageData(imageData, startBit, bodyLength);

      // Decrypt with AES-GCM
      const decryptedText = await decryptPayload(ciphertext, password, salt, iv);

      return {
        text: decryptedText,
        isEncrypted: true,
        cipherMethod: 'AES-256-GCM',
        size: bodyLength
      };
    } else if (flag === FLAG_PLAINTEXT) {
      // Plaintext payload
      const bodyBytes = extractBytesFromImageData(imageData, startBit, bodyLength);
      const dec = new TextDecoder();
      return {
        text: dec.decode(bodyBytes),
        isEncrypted: false,
        cipherMethod: 'None (Plaintext)',
        size: bodyLength
      };
    } else {
      throw new Error('Unrecognized packet flag. Data may be corrupted.');
    }
  }

  /* =========================================================================
     UI & EVENT CONTROLLERS
     ========================================================================= */

  /**
   * Displays toast notification.
   */
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
    } else if (type === 'error') {
      iconSvg = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
    } else {
      iconSvg = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
    }

    toast.innerHTML = `${iconSvg}<span>${message}</span>`;
    DOM.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  /**
   * Tab Navigation Switcher.
   */
  function setupTabs() {
    DOM.tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');

        DOM.tabBtns.forEach(b => b.classList.remove('active'));
        DOM.panelSections.forEach(s => s.classList.remove('active'));

        btn.classList.add('active');
        const targetSection = document.getElementById(targetId);
        if (targetSection) targetSection.classList.add('active');
      });
    });
  }

  /**
   * Password Visibility Toggle Helper.
   */
  function setupPasswordToggles() {
    const bindToggle = (btn, input) => {
      btn.addEventListener('click', () => {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        const eyeOpen = btn.querySelector('.eye-open');
        const eyeClosed = btn.querySelector('.eye-closed');
        if (eyeOpen && eyeClosed) {
          eyeOpen.classList.toggle('hidden', isPassword);
          eyeClosed.classList.toggle('hidden', !isPassword);
        }
      });
    };

    if (DOM.encodeTogglePw && DOM.encodePassword) {
      bindToggle(DOM.encodeTogglePw, DOM.encodePassword);
    }
    if (DOM.decodeTogglePw && DOM.decodePassword) {
      bindToggle(DOM.decodeTogglePw, DOM.decodePassword);
    }
  }

  /**
   * Password Strength Calculator.
   */
  function checkPasswordStrength(pw) {
    if (!pw) {
      DOM.strengthBar.style.setProperty('--strength-pct', '0%');
      DOM.strengthBar.style.setProperty('--strength-color', 'transparent');
      DOM.strengthText.textContent = 'Password strength: Empty';
      return;
    }

    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;

    let pct = '20%';
    let color = '#ef4444';
    let label = 'Very Weak';

    if (score === 2) {
      pct = '40%';
      color = '#f97316';
      label = 'Weak';
    } else if (score === 3) {
      pct = '65%';
      color = '#f59e0b';
      label = 'Moderate';
    } else if (score === 4) {
      pct = '85%';
      color = '#10b981';
      label = 'Strong';
    } else if (score >= 5) {
      pct = '100%';
      color = '#06b6d4';
      label = 'Very Strong';
    }

    DOM.strengthBar.style.setProperty('--strength-pct', pct);
    DOM.strengthBar.style.setProperty('--strength-color', color);
    DOM.strengthText.textContent = `Password strength: ${label}`;
  }

  /**
   * Updates capacity meter and secret character count.
   */
  function updateCapacityDisplay() {
    const text = DOM.secretMessage.value;
    const enc = new TextEncoder();
    const payloadBytes = enc.encode(text).length;

    DOM.secretCharCount.textContent = `${text.length} chars (${payloadBytes} bytes)`;

    if (state.encodeCapacityBytes > 0) {
      // Include estimated packet overhead: 9 header + (28 encryption bytes if enabled)
      const overhead = 9 + (DOM.enableEncryption.checked ? (SALT_LENGTH + IV_LENGTH + 16) : 0);
      const totalEstimatedBytes = payloadBytes > 0 ? (payloadBytes + overhead) : 0;
      const pct = Math.min(100, Math.round((totalEstimatedBytes / state.encodeCapacityBytes) * 100));

      const usedKB = (totalEstimatedBytes / 1024).toFixed(1);
      const totalKB = (state.encodeCapacityBytes / 1024).toFixed(1);

      DOM.capacityText.textContent = `${usedKB} / ${totalKB} KB (${pct}%)`;
      DOM.capacityBar.style.width = `${pct}%`;

      DOM.capacityBar.classList.remove('warning', 'danger');
      if (pct > 90) {
        DOM.capacityBar.classList.add('danger');
      } else if (pct > 70) {
        DOM.capacityBar.classList.add('warning');
      }
    } else {
      DOM.capacityText.textContent = '0 / 0 KB (0%)';
      DOM.capacityBar.style.width = '0%';
    }
  }

  /**
   * Image File Loader Helper.
   */
  function handleImageFile(file, isEncode) {
    if (!file || !file.type.startsWith('image/')) {
      showToast('Please select a valid image file (PNG, JPG, or WEBP).', 'error');
      return;
    }

    const reader = new FileReader();
    reader.onload = function (e) {
      const img = new Image();
      img.onload = function () {
        if (isEncode) {
          state.encodeImage = img;
          state.encodeImageDimensions = { width: img.naturalWidth, height: img.naturalHeight };
          state.encodeCapacityBytes = Math.floor((img.naturalWidth * img.naturalHeight * 3) / 8);

          DOM.encodePreviewImg.src = img.src;
          DOM.encodeImgInfo.textContent = `${img.naturalWidth} × ${img.naturalHeight} px (Capacity: ${(state.encodeCapacityBytes / 1024).toFixed(1)} KB)`;
          DOM.encodeDropContent.classList.add('hidden');
          DOM.encodePreviewWrapper.classList.remove('hidden');

          updateCapacityDisplay();
          showToast(`Cover image loaded (${img.naturalWidth}×${img.naturalHeight}px).`, 'success');
        } else {
          state.decodeImage = img;
          state.decodeImageDimensions = { width: img.naturalWidth, height: img.naturalHeight };

          DOM.decodePreviewImg.src = img.src;
          DOM.decodeImgInfo.textContent = `${img.naturalWidth} × ${img.naturalHeight} px`;
          DOM.decodeDropContent.classList.add('hidden');
          DOM.decodePreviewWrapper.classList.remove('hidden');

          showToast(`Stego image loaded (${img.naturalWidth}×${img.naturalHeight}px).`, 'success');
        }
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  /**
   * Drag & Drop event bindings.
   */
  function setupDragAndDrop() {
    // Encode Dropzone
    DOM.encodeFileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleImageFile(e.target.files[0], true);
      }
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      DOM.encodeDropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        DOM.encodeDropzone.classList.add('drag-over');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      DOM.encodeDropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        DOM.encodeDropzone.classList.remove('drag-over');
      });
    });

    DOM.encodeDropzone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleImageFile(e.dataTransfer.files[0], true);
      }
    });

    DOM.encodeRemoveImg.addEventListener('click', (e) => {
      e.stopPropagation();
      state.encodeImage = null;
      state.encodeCapacityBytes = 0;
      DOM.encodeFileInput.value = '';
      DOM.encodePreviewWrapper.classList.add('hidden');
      DOM.encodeDropContent.classList.remove('hidden');
      updateCapacityDisplay();
    });

    // Decode Dropzone
    DOM.decodeFileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleImageFile(e.target.files[0], false);
      }
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      DOM.decodeDropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        DOM.decodeDropzone.classList.add('drag-over');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      DOM.decodeDropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        DOM.decodeDropzone.classList.remove('drag-over');
      });
    });

    DOM.decodeDropzone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleImageFile(e.dataTransfer.files[0], false);
      }
    });

    DOM.decodeRemoveImg.addEventListener('click', (e) => {
      e.stopPropagation();
      state.decodeImage = null;
      DOM.decodeFileInput.value = '';
      DOM.decodePreviewWrapper.classList.add('hidden');
      DOM.decodeDropContent.classList.remove('hidden');
    });
  }

  /**
   * Setup form listeners.
   */
  function setupFormListeners() {
    DOM.secretMessage.addEventListener('input', updateCapacityDisplay);

    DOM.enableEncryption.addEventListener('change', () => {
      DOM.encodePasswordWrapper.style.display = DOM.enableEncryption.checked ? 'flex' : 'none';
      updateCapacityDisplay();
    });

    DOM.encodePassword.addEventListener('input', (e) => {
      checkPasswordStrength(e.target.value);
    });

    // Copy to clipboard
    DOM.btnCopyExtracted.addEventListener('click', async () => {
      const text = DOM.extractedTextArea.value;
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        showToast('Secret message copied to clipboard!', 'success');
      } catch (err) {
        DOM.extractedTextArea.select();
        document.execCommand('copy');
        showToast('Secret message copied to clipboard!', 'success');
      }
    });
  }

  /**
   * Encode & Embed Workflow.
   */
  async function handleEncode() {
    if (!state.encodeImage) {
      showToast('Please upload a cover image first.', 'error');
      DOM.encodeDropzone.scrollIntoView({ behavior: 'smooth' });
      return;
    }

    const secretText = DOM.secretMessage.value;
    if (!secretText || secretText.trim() === '') {
      showToast('Please enter a secret message to conceal.', 'error');
      DOM.secretMessage.focus();
      return;
    }

    const isEncrypted = DOM.enableEncryption.checked;
    const password = DOM.encodePassword.value;

    if (isEncrypted && (!password || password.length < 4)) {
      showToast('Please enter an encryption password of at least 4 characters.', 'error');
      DOM.encodePassword.focus();
      return;
    }

    const originalBtnHtml = DOM.btnEncode.innerHTML;
    DOM.btnEncode.disabled = true;
    DOM.btnEncode.innerHTML = `
      <svg class="spin" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="12" y1="2" x2="12" y2="6"/>
        <line x1="12" y1="18" x2="12" y2="22"/>
        <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/>
        <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/>
        <line x1="2" y1="12" x2="6" y2="12"/>
        <line x1="18" y1="12" x2="22" y2="12"/>
      </svg>
      <span>Processing Stego Carrier...</span>
    `;

    try {
      // Step 1: Draw cover image to Canvas
      const canvas = DOM.hiddenCanvas;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      canvas.width = state.encodeImageDimensions.width;
      canvas.height = state.encodeImageDimensions.height;
      ctx.drawImage(state.encodeImage, 0, 0);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      // Step 2: Encrypt or Encode body
      let packet;
      let payloadSize = 0;

      if (isEncrypted) {
        const encrypted = await encryptPayload(secretText, password);
        payloadSize = encrypted.ciphertext.length;
        packet = buildStegoPacket(FLAG_ENCRYPTED, payloadSize, encrypted.salt, encrypted.iv, encrypted.ciphertext);
      } else {
        const enc = new TextEncoder();
        const plainBytes = enc.encode(secretText);
        payloadSize = plainBytes.length;
        packet = buildStegoPacket(FLAG_PLAINTEXT, payloadSize, null, null, plainBytes);
      }

      // Step 3: Embed packet into LSB
      embedPacketInImageData(imageData, packet);
      ctx.putImageData(imageData, 0, 0);

      // Step 4: Export lossless PNG blob
      canvas.toBlob((blob) => {
        if (!blob) {
          throw new Error('Canvas export failed.');
        }

        if (state.activeBlobUrl) {
          URL.revokeObjectURL(state.activeBlobUrl);
        }

        state.activeBlobUrl = URL.createObjectURL(blob);
        DOM.encodeResultImg.src = state.activeBlobUrl;
        DOM.btnDownloadStego.href = state.activeBlobUrl;
        DOM.btnDownloadStego.download = `stego-secure-${Date.now()}.png`;

        // Update Result Metadata
        DOM.resMetaSize.textContent = `${packet.length} bytes`;
        DOM.resMetaEnc.textContent = isEncrypted ? 'AES-256-GCM (PBKDF2)' : 'Plaintext (Unencrypted)';
        
        const totalPixels = canvas.width * canvas.height;
        const pixelsModified = Math.ceil((packet.length * 8) / 3);
        const modifiedPct = ((pixelsModified / totalPixels) * 100).toFixed(2);
        DOM.resMetaPixels.textContent = `${modifiedPct}% (${pixelsModified.toLocaleString()} px)`;

        DOM.encodeResultPlaceholder.classList.add('hidden');
        DOM.encodeResultActive.classList.remove('hidden');

        showToast('Secret payload encrypted & embedded successfully!', 'success');
      }, 'image/png');

    } catch (err) {
      console.error(err);
      showToast(`Embedding Error: ${err.message}`, 'error');
    } finally {
      DOM.btnEncode.disabled = false;
      DOM.btnEncode.innerHTML = originalBtnHtml;
    }
  }

  /**
   * Decode & Extract Workflow.
   */
  async function handleDecode() {
    if (!state.decodeImage) {
      showToast('Please upload a stego image to extract from.', 'error');
      DOM.decodeDropzone.scrollIntoView({ behavior: 'smooth' });
      return;
    }

    const password = DOM.decodePassword.value;
    const originalBtnHtml = DOM.btnDecode.innerHTML;

    DOM.btnDecode.disabled = true;
    DOM.btnDecode.innerHTML = `
      <svg class="spin" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="12" y1="2" x2="12" y2="6"/>
        <line x1="12" y1="18" x2="12" y2="22"/>
      </svg>
      <span>Scanning Bitplanes...</span>
    `;

    try {
      const canvas = DOM.hiddenCanvas;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      canvas.width = state.decodeImageDimensions.width;
      canvas.height = state.decodeImageDimensions.height;
      ctx.drawImage(state.decodeImage, 0, 0);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      const result = await extractStegoPayload(imageData, password);

      DOM.extractedTextArea.value = result.text;
      DOM.decodePayloadLength.textContent = `${result.text.length} characters (${result.size} bytes)`;
      DOM.decodeMetaCipher.textContent = result.cipherMethod;

      if (result.isEncrypted) {
        DOM.decodeChipText.textContent = 'Authenticated & Decrypted';
        DOM.decodeStatusChip.style.background = 'rgba(16, 185, 129, 0.15)';
        DOM.decodeStatusChip.style.color = '#10b981';
        DOM.decodeMetaIntegrity.textContent = 'Passed (Valid GCM Tag)';
      } else {
        DOM.decodeChipText.textContent = 'Extracted (Plaintext)';
        DOM.decodeStatusChip.style.background = 'rgba(6, 182, 212, 0.15)';
        DOM.decodeStatusChip.style.color = '#06b6d4';
        DOM.decodeMetaIntegrity.textContent = 'Unencrypted (No Tag)';
      }

      DOM.decodeResultPlaceholder.classList.add('hidden');
      DOM.decodeResultActive.classList.remove('hidden');

      showToast('Secret message successfully extracted!', 'success');

    } catch (err) {
      console.error(err);
      showToast(err.message, 'error');
    } finally {
      DOM.btnDecode.disabled = false;
      DOM.btnDecode.innerHTML = originalBtnHtml;
    }
  }

  /**
   * Initializes application listeners and state.
   */
  function init() {
    setupTabs();
    setupPasswordToggles();
    setupDragAndDrop();
    setupFormListeners();

    DOM.btnEncode.addEventListener('click', handleEncode);
    DOM.btnDecode.addEventListener('click', handleDecode);

    console.log('StegoShield initialized. Ready for secure client-side steganography.');
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
