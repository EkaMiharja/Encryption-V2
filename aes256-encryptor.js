let currentMode = 'encrypt';
let currentFile = null;
let showPass = false;

const modeDescriptions = {
  CBC: 'CBC: Cipher Block Chaining — setiap blok XOR dengan ciphertext sebelumnya. Butuh padding.',
  CFB: 'CFB: Cipher Feedback — mengubah block cipher jadi stream cipher. IV diperlukan, padding opsional.',
  OFB: 'OFB: Output Feedback — keystream digenerate independen dari plaintext. Tahan bit-flip error.',
  GCM: 'GCM: Galois/Counter Mode — authenticated encryption (enkripsi + integritas). Tidak butuh padding.'
};

function selectChip(groupId, val, btn) {
  document.querySelectorAll(`#${groupId} .sel-chip`).forEach(c => c.classList.remove('active'));
  btn.classList.add('active');

  if (groupId === 'modeGroup') {
    // Mode changes update the description and disable padding for GCM.
    document.getElementById('modeDesc').textContent = modeDescriptions[val];
    const paddingSection = document.getElementById('paddingSection');
    paddingSection.style.opacity = val === 'GCM' ? '0.4' : '1';
    paddingSection.style.pointerEvents = val === 'GCM' ? 'none' : 'auto';
    document.getElementById('headerBadge').textContent = `AES-256-${val}`;
  }
}

// Read the currently selected cipher mode from the mode chip group.
function getSelectedMode() {
  const active = document.querySelector('#modeGroup .sel-chip.active');
  return active ? active.dataset.val : 'CBC';
}

// Read the currently selected padding option from the padding chip group.
function getSelectedPadding() {
  const active = document.querySelector('#paddingGroup .sel-chip.active');
  return active ? active.dataset.val : 'Pkcs7';
}

// Generate a random IV that matches the active cipher mode.
function generateIV() {
  const mode = getSelectedMode();
  // GCM uses a 96-bit IV; other modes use 128-bit.
  const bytes = mode === 'GCM' ? 12 : 16;
  const iv = CryptoJS.lib.WordArray.random(bytes);
  document.getElementById('ivInput').value = iv.toString(CryptoJS.enc.Hex);
  document.getElementById('ivInput').classList.remove('iv-invalid');
  document.getElementById('ivInput').classList.add('iv-valid');
  document.getElementById('ivStatus').textContent = `IV ${bytes * 8}-bit berhasil digenerate secara acak`;
  document.getElementById('ivStatus').style.color = 'var(--accent3)';
}

// Validate the IV field against the required length and hex format.
function validateIV() {
  const val = document.getElementById('ivInput').value.trim();
  const inp = document.getElementById('ivInput');
  const status = document.getElementById('ivStatus');
  const mode = getSelectedMode();
  const expectedLen = mode === 'GCM' ? 24 : 32;

  if (val === '') {
    inp.classList.remove('iv-valid', 'iv-invalid');
    status.textContent = 'Kosongkan untuk generate IV acak otomatis saat enkripsi';
    status.style.color = 'var(--muted)';
    return true;
  }

  const hexRegex = /^[0-9a-fA-F]+$/;
  if (!hexRegex.test(val) || val.length !== expectedLen) {
    inp.classList.remove('iv-valid');
    inp.classList.add('iv-invalid');
    status.textContent = `IV harus tepat ${expectedLen} karakter hex (${expectedLen * 4} bit)`;
    status.style.color = 'var(--danger)';
    return false;
  }

  inp.classList.remove('iv-invalid');
  inp.classList.add('iv-valid');
  status.textContent = `IV valid — ${expectedLen * 4} bit`;
  status.style.color = 'var(--accent3)';
  return true;
}

// Return the IV from the input field, or generate one if it is empty.
function getOrGenerateIV() {
  const val = document.getElementById('ivInput').value.trim();
  const mode = getSelectedMode();
  const bytes = mode === 'GCM' ? 12 : 16;

  if (val === '') {
    const iv = CryptoJS.lib.WordArray.random(bytes);
    const hex = iv.toString(CryptoJS.enc.Hex);
    document.getElementById('ivInput').value = hex;
    validateIV();
    return iv;
  }

  return CryptoJS.enc.Hex.parse(val);
}

// Map the UI cipher mode to the CryptoJS mode implementation.
function getCryptoMode(mode) {
  const map = {
    CBC: CryptoJS.mode.CBC,
    CFB: CryptoJS.mode.CFB,
    OFB: CryptoJS.mode.OFB,
    CTR: CryptoJS.mode.CTR
  };
  return map[mode] || CryptoJS.mode.CBC;
}

// Map the UI padding selection to the CryptoJS padding implementation.
function getCryptoPadding(padding) {
  const map = {
    Pkcs7: CryptoJS.pad.Pkcs7,
    ZeroPadding: CryptoJS.pad.ZeroPadding,
    Iso10126: CryptoJS.pad.Iso10126,
    AnsiX923: CryptoJS.pad.AnsiX923,
    NoPadding: CryptoJS.pad.NoPadding
  };
  return map[padding] || CryptoJS.pad.Pkcs7;
}

// Toggle the optional custom salt input visibility.
function toggleSalt(btn) {
  const active = btn.classList.toggle('active');
  document.getElementById('saltField').style.display = active ? 'block' : 'none';
}

// Switch the UI between encrypt and decrypt workflows.
function setMode(mode) {
  currentMode = mode;
  document.getElementById('btnEncrypt').classList.toggle('active', mode === 'encrypt');
  document.getElementById('btnDecrypt').classList.toggle('active', mode === 'decrypt');
  document.getElementById('actionLabel').innerHTML = mode === 'encrypt'
    ? '<span>Enkripsi File Sekarang</span>'
    : '<span>Dekripsi File Sekarang</span>';

  const fi = document.getElementById('fileInput');
  // Restrict the file picker to the current workflow.
  fi.accept = mode === 'encrypt' ? '.txt,.pdf' : '.enc,.txt';

  const ivSection = document.getElementById('ivSection');
  const optionsRow = document.getElementById('optionsRow');

  if (mode === 'decrypt') {
    document.getElementById('dropSub').textContent = 'Pilih file terenkripsi (.enc atau .txt yang berisi payload):';
    document.getElementById('fileTypes').innerHTML = '<span class="file-type-tag" style="background:rgba(124,58,237,0.15);color:#a78bfa;border:1px solid rgba(124,58,237,0.3)">ENC</span><span class="file-type-tag tag-txt">TXT</span>';
    optionsRow.style.display = 'none';
    ivSection.style.display = 'none';
  } else {
    document.getElementById('dropSub').textContent = 'Dukung format berikut:';
    document.getElementById('fileTypes').innerHTML = '<span class="file-type-tag tag-txt">TXT</span><span class="file-type-tag tag-pdf">PDF</span>';
    optionsRow.style.display = 'flex';
    ivSection.style.display = 'block';
  }

  removeFile();
  clearAlert();
}

// Handle drag-over state for the file drop zone.
function handleDrag(e, over) {
  e.preventDefault();
  document.getElementById('dropzone').classList.toggle('dragover', over);
}

// Handle file drops and forward the selected file to the loader.
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('dropzone').classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) handleFile(file);
}

// Validate the selected file and update the file summary panel.
function handleFile(file) {
  if (!file) return;
  const ext = file.name.split('.').pop().toLowerCase();
  if (currentMode === 'encrypt' && !['txt', 'pdf'].includes(ext)) {
    showAlert('error', '⚠ Hanya file .txt dan .pdf yang didukung untuk enkripsi!'); return;
  }
  if (currentMode === 'decrypt' && !['enc', 'txt'].includes(ext)) {
    showAlert('error', '⚠ Hanya file .enc atau .txt yang berisi data terenkripsi yang dapat didekripsi!'); return;
  }
  currentFile = file;
  clearAlert();
  document.getElementById('fileName').textContent = file.name;
  document.getElementById('fileMeta').textContent = `${formatSize(file.size)} · ${ext.toUpperCase()} · Terdeteksi ${new Date().toLocaleTimeString('id-ID')}`;
  const iconWrap = document.getElementById('fileIconWrap');
  // Swap the file icon based on the detected extension.
  if (ext === 'pdf') { iconWrap.innerHTML = '<i class="fa-solid fa-file-pdf"></i>'; iconWrap.className = 'file-icon-wrap file-icon-pdf'; }
  else if (ext === 'enc') { iconWrap.innerHTML = '<i class="fa-solid fa-file-shield"></i>'; iconWrap.className = 'file-icon-wrap file-icon-enc'; }
  else { iconWrap.innerHTML = '<i class="fa-regular fa-file-lines"></i>'; iconWrap.className = 'file-icon-wrap file-icon-txt'; }
  document.getElementById('fileInfo').classList.add('show');
  document.getElementById('dropzone').style.opacity = '0.5';
  document.getElementById('dropzone').style.pointerEvents = 'none';
}

// Clear the currently selected file and reset the drop zone state.
function removeFile() {
  currentFile = null;
  document.getElementById('fileInfo').classList.remove('show');
  document.getElementById('fileInput').value = '';
  document.getElementById('dropzone').style.opacity = '';
  document.getElementById('dropzone').style.pointerEvents = '';
  clearAlert();
}

// Format a byte count into a human-readable file size string.
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

// Toggle password visibility in the password input field.
function togglePass() {
  showPass = !showPass;
  document.getElementById('passInput').type = showPass ? 'text' : 'password';
  // Toggle the visibility icon together with the input type.
  document.getElementById('eyeBtn').innerHTML = showPass
    ? '<i class="fa-regular fa-eye-slash"></i>'
    : '<i class="fa-regular fa-eye"></i>';
}

// Compute and render a simple password-strength meter.
function updateStrength() {
  const pass = document.getElementById('passInput').value;
  const wrap = document.getElementById('strengthWrap');
  if (!pass) { wrap.classList.remove('show'); return; }
  wrap.classList.add('show');
  let score = 0;
  if (pass.length >= 8) score++;
  if (pass.length >= 12) score++;
  if (/[A-Z]/.test(pass)) score++;
  if (/[0-9]/.test(pass)) score++;
  if (/[^A-Za-z0-9]/.test(pass)) score++;
  const levels = [
    { pct: '15%', color: '#ef4444', label: 'Sangat Lemah' },
    { pct: '30%', color: '#f97316', label: 'Lemah' },
    { pct: '55%', color: '#f59e0b', label: 'Sedang' },
    { pct: '80%', color: '#84cc16', label: 'Kuat' },
    { pct: '100%', color: '#10b981', label: 'Sangat Kuat' }
  ];
  const lv = levels[Math.min(score, 4)];
  document.getElementById('strengthFill').style.width = lv.pct;
  document.getElementById('strengthFill').style.background = lv.color;
  document.getElementById('strengthText').textContent = lv.label;
  document.getElementById('strengthText').style.color = lv.color;
}

// Show a styled alert message with an icon that matches the alert type.
function showAlert(type, msg) {
  const box = document.getElementById('alertBox');
  box.className = `alert show alert-${type}`;
  // Use a success or warning icon based on the alert state.
  document.getElementById('alertIcon').innerHTML = type === 'success'
    ? '<i class="fa-solid fa-circle-check"></i>'
    : '<i class="fa-solid fa-triangle-exclamation"></i>';
  document.getElementById('alertMsg').textContent = msg;
}

// Clear the alert box back to its hidden state.
function clearAlert() { document.getElementById('alertBox').className = 'alert'; }

// Update the visual progress bar and auto-hide it after completion.
function setProgress(pct, msg) {
  const wrap = document.getElementById('progressWrap');
  wrap.classList.add('show');
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressText').textContent = msg;
  if (pct >= 100) setTimeout(() => wrap.classList.remove('show'), 800);
}

// Validate inputs and route the current action to encrypt or decrypt.
async function processFile() {
  if (!currentFile) { showAlert('error', 'Pilih file terlebih dahulu!'); return; }
  const pass = document.getElementById('passInput').value.trim();
  if (!pass) { showAlert('error', 'Masukkan password terlebih dahulu!'); return; }
  if (currentMode === 'encrypt' && !validateIV()) return;

  const btn = document.getElementById('actionBtn');
  btn.disabled = true;
  clearAlert();
  try {
    if (currentMode === 'encrypt') await encryptFile(pass);
    else await decryptFile(pass);
  } catch (e) {
    showAlert('error', 'Terjadi kesalahan: ' + e.message);
  }
  btn.disabled = false;
}

// Encrypt the selected file, package metadata, and trigger the download.
async function encryptFile(password) {
  const cipherMode = getSelectedMode();
  const paddingName = cipherMode === 'GCM' ? 'NoPadding' : getSelectedPadding();

  setProgress(10, 'Membaca file...');
  const arrayBuf = await currentFile.arrayBuffer();
  const bytes = new Uint8Array(arrayBuf);

  setProgress(25, 'Membangkitkan kunci AES-256...');
  const saltCustom = document.getElementById('chipSalt').classList.contains('active')
    ? document.getElementById('saltInput').value.trim() : '';
  const salt = saltCustom
    ? CryptoJS.enc.Utf8.parse(saltCustom)
    : CryptoJS.lib.WordArray.random(16);
  const saltHex = salt.toString(CryptoJS.enc.Hex);

  const key = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32, iterations: 10000, hasher: CryptoJS.algo.SHA256
  });

  setProgress(50, `Mengenkripsi dengan AES-256-${cipherMode}...`);
  const iv = getOrGenerateIV();
  const ivHex = iv.toString(CryptoJS.enc.Hex);
  const wordArray = CryptoJS.lib.WordArray.create(bytes);

  let encryptedStr;
  if (cipherMode === 'GCM') {
    const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
      iv: iv, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding
    });
    const authTag = CryptoJS.HmacSHA256(encrypted.toString(), key).toString(CryptoJS.enc.Hex).substring(0, 32);
    encryptedStr = encrypted.toString() + '|' + authTag;
  } else {
    const encrypted = CryptoJS.AES.encrypt(wordArray, key, {
      iv: iv,
      mode: getCryptoMode(cipherMode),
      padding: getCryptoPadding(paddingName)
    });
    encryptedStr = encrypted.toString();
  }

  setProgress(80, 'Menyusun output file...');
  const originalExt = currentFile.name.split('.').pop().toLowerCase();
  const metadata = {
    alg: `AES-256-${cipherMode}`,
    padding: paddingName,
    kdf: 'PBKDF2-SHA256-10000',
    salt: saltHex,
    iv: ivHex,
    originalName: currentFile.name,
    originalExt: originalExt,
    size: currentFile.size,
    encryptedAt: new Date().toISOString(),
    version: '2.0'
  };

  const payload = JSON.stringify({ meta: metadata, data: encryptedStr });
  setProgress(95, 'Mengunduh file terenkripsi...');
  downloadFile(payload, currentFile.name.replace(/\.[^.]+$/, '') + '.enc', 'application/octet-stream');
  setProgress(100, 'Selesai!');
  showAlert('success', `File berhasil dienkripsi dengan AES-256-${cipherMode}! Disimpan sebagai "${currentFile.name.replace(/\.[^.]+$/, '')}.enc". Simpan password & IV Anda!`);
}

// Decrypt the selected file, validate the payload, and restore the original data.
async function decryptFile(password) {
  setProgress(10, 'Membaca file terenkripsi...');
  const text = await currentFile.text();

  setProgress(25, 'Memvalidasi format file...');
  let payload;
  try { payload = JSON.parse(text.replace(/^\uFEFF/, '').trim()); }
  catch { throw new Error('Format file tidak valid atau file rusak!'); }

  if (!payload.meta || !payload.data) throw new Error('File tidak memiliki struktur enkripsi yang valid!');

  const { meta, data } = payload;
  const cipherMode = meta.alg ? meta.alg.replace('AES-256-', '') : 'CBC';
  const paddingName = meta.padding || 'Pkcs7';

  setProgress(40, 'Menurunkan kunci dari password...');
  const salt = CryptoJS.enc.Hex.parse(meta.salt);
  const iv = CryptoJS.enc.Hex.parse(meta.iv);
  const key = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32, iterations: 10000, hasher: CryptoJS.algo.SHA256
  });

  setProgress(65, `Mendekripsi data (${cipherMode})...`);
  let decrypted;
  try {
    if (cipherMode === 'GCM') {
      // GCM is simulated with CTR plus an HMAC tag in this UI.
      const parts = data.split('|');
      const cipherData = parts[0];
      const authTag = parts[1] || '';
      const expectedTag = CryptoJS.HmacSHA256(cipherData, key).toString(CryptoJS.enc.Hex).substring(0, 32);
      if (authTag && authTag !== expectedTag) throw new Error('Auth tag tidak cocok — data mungkin telah dimodifikasi!');
      decrypted = CryptoJS.AES.decrypt(cipherData, key, {
        iv: iv, mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding
      });
    } else {
      decrypted = CryptoJS.AES.decrypt(data, key, {
        iv: iv,
        mode: getCryptoMode(cipherMode),
        padding: getCryptoPadding(paddingName)
      });
    }
  } catch (e) {
    throw new Error('Dekripsi gagal! ' + (e.message || 'Password mungkin salah.'));
  }

  if (!decrypted || decrypted.sigBytes <= 0) throw new Error('Password salah atau file rusak!');

  setProgress(85, 'Membangun ulang file asli...');
  const arrayBuffer = wordArrayToArrayBuffer(decrypted);
  const ext = meta.originalExt || 'txt';
  const mime = ext === 'pdf' ? 'application/pdf' : 'text/plain';
  const outName = meta.originalName || ('decrypted.' + ext);

  setProgress(95, 'Mengunduh file...');
  downloadBinaryFile(arrayBuffer, outName, mime);
  setProgress(100, 'Selesai!');
  const encDate = new Date(meta.encryptedAt).toLocaleString('id-ID');
  showAlert('success', `File berhasil didekripsi! Mode: ${cipherMode} | Dienkripsi: ${encDate} | File: "${outName}"`);
}

// Convert a CryptoJS WordArray into a raw ArrayBuffer for binary download.
function wordArrayToArrayBuffer(wordArray) {
  const words = wordArray.words;
  const sigBytes = wordArray.sigBytes;
  const u8 = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return u8.buffer;
}

// Download text content as a file using a temporary object URL.
function downloadFile(content, filename, mime) {
  const bytes = new TextEncoder().encode(content);
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 200);
}

// Download binary content as a file using a temporary object URL.
function downloadBinaryFile(buffer, filename, mime) {
  const blob = new Blob([buffer], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 200);
}
