'use strict';

/**
 * AuthGuard Module - Authenticatie & 2FA voor Knowledge by Data applicaties
 * Wachtwoordbeveiliging (PBKDF2-SHA256) + TOTP twee-factor authenticatie
 * Volledig in-browser, geen externe afhankelijkheden
 *
 * Copyright 2026 Knowledge by Data B.V.
 *
 * CONFIGURATIE:
 *   Pas AUTH_CONFIG.APP_NAME en AUTH_CONFIG.APP_IDENTIFIER aan per applicatie.
 *   De storage keys worden automatisch afgeleid van APP_IDENTIFIER.
 */

// ============================================================================
// APPLICATIE-SPECIFIEKE CONFIGURATIE — PAS DIT AAN PER APP
// ============================================================================
const AUTH_APP_NAME = 'Vergunning Intake Pro';
const AUTH_APP_IDENTIFIER = 'vergunning-intake-pro';
// ============================================================================

const AUTH_CONFIG = Object.freeze({
  APP_NAME: AUTH_APP_NAME,
  APP_IDENTIFIER: AUTH_APP_IDENTIFIER,
  PASSWORD_MIN_LENGTH: 12,
  PASSWORD_SALT_LENGTH: 16,
  PBKDF2_ITERATIONS: 100000,
  PBKDF2_HASH_ALGORITHM: 'SHA-256',
  TOTP_SECRET_LENGTH: 20,
  TOTP_DIGITS: 6,
  TOTP_PERIOD: 30,
  TOTP_WINDOW: 1,
  SESSION_DURATION_MS: 8 * 60 * 60 * 1000,
  STORAGE_KEY_CONFIG: AUTH_APP_IDENTIFIER + '-auth-config',
  STORAGE_KEY_TOTP: AUTH_APP_IDENTIFIER + '-totp-encrypted',
  STORAGE_KEY_SESSION: AUTH_APP_IDENTIFIER + '-session',
  STORAGE_KEY_ATTEMPTS: AUTH_APP_IDENTIFIER + '-attempts',
  BRUTE_FORCE_BACKOFF_MS: [0, 0, 5000, 15000, 30000, 60000, 120000],
});

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// ============================================================================
// CRYPTOGRAFISCHE HULPFUNCTIES
// ============================================================================

async function generateRandomBytes(length) {
  const buffer = new Uint8Array(length);
  crypto.getRandomValues(buffer);
  return buffer;
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bufferToBase32(buffer) {
  const bytes = new Uint8Array(buffer);
  let result = '';
  let bits = 0;
  let value = 0;

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32_ALPHABET[(value >> bits) & 31];
    }
  }

  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return result;
}

function base32ToBuffer(base32) {
  const base32Upper = base32.toUpperCase().replace(/=/g, '');
  const bytes = [];
  let bits = 0;
  let value = 0;

  for (let i = 0; i < base32Upper.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(base32Upper[i]);
    if (idx === -1) throw new Error('Invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 255);
    }
  }

  return new Uint8Array(bytes).buffer;
}

function formatSecretForDisplay(secret) {
  return secret.match(/.{1,4}/g).join(' ');
}

// ============================================================================
// WACHTWOORD VALIDATIE & HASHING (PBKDF2-SHA256)
// ============================================================================

function validatePassword(password) {
  if (password.length < AUTH_CONFIG.PASSWORD_MIN_LENGTH) {
    return { valid: false, error: 'Minimaal ' + AUTH_CONFIG.PASSWORD_MIN_LENGTH + ' tekens vereist' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: 'Minimaal \u00e9\u00e9n hoofdletter vereist' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, error: 'Minimaal \u00e9\u00e9n kleine letter vereist' };
  }
  if (!/\d/.test(password)) {
    return { valid: false, error: 'Minimaal \u00e9\u00e9n cijfer vereist' };
  }
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return { valid: false, error: 'Minimaal \u00e9\u00e9n speciaal teken vereist' };
  }
  return { valid: true };
}

async function hashPassword(password, saltBuffer) {
  if (!saltBuffer) {
    saltBuffer = await generateRandomBytes(AUTH_CONFIG.PASSWORD_SALT_LENGTH);
  }

  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const keyBuffer = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: AUTH_CONFIG.PBKDF2_ITERATIONS,
      hash: AUTH_CONFIG.PBKDF2_HASH_ALGORITHM,
    },
    keyBuffer,
    256
  );

  return {
    salt: bufferToBase64(saltBuffer),
    hash: bufferToBase64(derivedBits),
  };
}

async function verifyPassword(password, config) {
  const saltBuffer = base64ToBuffer(config.salt);
  const hashResult = await hashPassword(password, saltBuffer);
  return hashResult.hash === config.hash;
}

// ============================================================================
// TOTP (RFC 6238) — HMAC-SHA1
// ============================================================================

async function generateTotpSecret() {
  return await generateRandomBytes(AUTH_CONFIG.TOTP_SECRET_LENGTH);
}

async function generateTotpCode(secretBuffer, timestamp) {
  if (!timestamp) {
    timestamp = Math.floor(Date.now() / 1000);
  }

  let counter = Math.floor(timestamp / AUTH_CONFIG.TOTP_PERIOD);
  const counterBuffer = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    counterBuffer[i] = counter & 0xff;
    counter >>= 8;
  }

  const key = await crypto.subtle.importKey(
    'raw',
    secretBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const hmac = await crypto.subtle.sign('HMAC', key, counterBuffer.buffer);
  const hmacBytes = new Uint8Array(hmac);

  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const code = (
    ((hmacBytes[offset] & 0x7f) << 24) |
    ((hmacBytes[offset + 1] & 0xff) << 16) |
    ((hmacBytes[offset + 2] & 0xff) << 8) |
    (hmacBytes[offset + 3] & 0xff)
  ) % Math.pow(10, AUTH_CONFIG.TOTP_DIGITS);

  return code.toString().padStart(AUTH_CONFIG.TOTP_DIGITS, '0');
}

async function verifyTotpCode(secretBuffer, code) {
  const currentTimestamp = Math.floor(Date.now() / 1000);

  for (let i = -AUTH_CONFIG.TOTP_WINDOW; i <= AUTH_CONFIG.TOTP_WINDOW; i++) {
    const testTimestamp = currentTimestamp + (i * AUTH_CONFIG.TOTP_PERIOD);
    const testCode = await generateTotpCode(secretBuffer, testTimestamp);
    if (testCode === code) {
      return true;
    }
  }

  return false;
}

// ============================================================================
// TOTP SECRET VERSLEUTELING (AES-256-GCM)
// ============================================================================

async function deriveEncryptionKey(password) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // App-specifieke salt afgeleid van identifier
  const saltSource = new TextEncoder().encode(AUTH_CONFIG.APP_IDENTIFIER + '-totp-encryption-salt');
  const saltHash = await crypto.subtle.digest('SHA-256', saltSource);
  const salt = new Uint8Array(saltHash).slice(0, 16);

  const keyBuffer = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, [
    'deriveBits',
  ]);

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 50000,
      hash: 'SHA-256',
    },
    keyBuffer,
    256
  );

  return await crypto.subtle.importKey('raw', derivedBits, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

async function encryptTotpSecret(secretBuffer, password) {
  const encryptionKey = await deriveEncryptionKey(password);
  const iv = await generateRandomBytes(12);

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    encryptionKey,
    secretBuffer
  );

  return {
    iv: bufferToBase64(iv),
    encrypted: bufferToBase64(encryptedBuffer),
  };
}

async function decryptTotpSecret(encryptedData, password) {
  const encryptionKey = await deriveEncryptionKey(password);
  const iv = base64ToBuffer(encryptedData.iv);
  const encryptedBuffer = base64ToBuffer(encryptedData.encrypted);

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    encryptionKey,
    encryptedBuffer
  );

  return decryptedBuffer;
}

// ============================================================================
// BRUTE FORCE BESCHERMING
// ============================================================================

function getBackoffDuration(attemptCount) {
  if (attemptCount >= AUTH_CONFIG.BRUTE_FORCE_BACKOFF_MS.length) {
    return AUTH_CONFIG.BRUTE_FORCE_BACKOFF_MS[AUTH_CONFIG.BRUTE_FORCE_BACKOFF_MS.length - 1];
  }
  return AUTH_CONFIG.BRUTE_FORCE_BACKOFF_MS[attemptCount];
}

function recordFailedAttempt() {
  const attemptsData = sessionStorage.getItem(AUTH_CONFIG.STORAGE_KEY_ATTEMPTS);
  let attempts;

  if (attemptsData) {
    try {
      attempts = JSON.parse(attemptsData);
      attempts.count += 1;
      attempts.lastAttemptTime = Date.now();
    } catch {
      attempts = { count: 1, lastAttemptTime: Date.now() };
    }
  } else {
    attempts = { count: 1, lastAttemptTime: Date.now() };
  }

  sessionStorage.setItem(AUTH_CONFIG.STORAGE_KEY_ATTEMPTS, JSON.stringify(attempts));
}

// ============================================================================
// SESSIE BEHEER
// ============================================================================

function createSession() {
  const session = {
    authenticated: true,
    timestamp: Date.now(),
  };
  sessionStorage.setItem(AUTH_CONFIG.STORAGE_KEY_SESSION, JSON.stringify(session));
}

function getSession() {
  const sessionData = sessionStorage.getItem(AUTH_CONFIG.STORAGE_KEY_SESSION);
  if (!sessionData) return null;

  try {
    const session = JSON.parse(sessionData);
    const age = Date.now() - session.timestamp;

    if (age > AUTH_CONFIG.SESSION_DURATION_MS) {
      sessionStorage.removeItem(AUTH_CONFIG.STORAGE_KEY_SESSION);
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

// ============================================================================
// HTML ESCAPING
// ============================================================================

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================================================
// SETUP-SCHERM (EERSTE GEBRUIK)
// ============================================================================

function renderSetupScreen(container, onSuccess) {
  const appName = escapeHtml(AUTH_CONFIG.APP_NAME);
  const setupHtml = '<div class="auth-guard-container auth-guard-setup">' +
    '<div class="auth-guard-card">' +
      '<div class="auth-guard-header">' +
        '<div class="auth-guard-logo">' +
          '<svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">' +
            '<rect width="48" height="48" rx="12" fill="var(--color-primary, #0066cc)" opacity="0.1"/>' +
            '<path d="M24 12L14 18V30L24 36L34 30V18L24 12Z" stroke="var(--color-primary, #0066cc)" stroke-width="2" fill="none"/>' +
            '<path d="M24 20V28M20 24H28" stroke="var(--color-primary, #0066cc)" stroke-width="2" stroke-linecap="round"/>' +
          '</svg>' +
        '</div>' +
        '<h1 class="auth-guard-title">' + appName + '</h1>' +
        '<p class="auth-guard-subtitle">Eerste keer instellen</p>' +
        '<p class="auth-guard-org">Knowledge by Data B.V.</p>' +
      '</div>' +

      '<div class="auth-guard-content">' +
        '<div class="auth-guard-step auth-guard-step-active" data-step="1">' +
          '<h2 class="auth-guard-step-title">Stap 1: Beveiligd wachtwoord instellen</h2>' +
          '<p class="auth-guard-step-description">Kies een sterk wachtwoord om de applicatie te beschermen.</p>' +

          '<div class="auth-guard-form-group">' +
            '<label for="setup-password" class="auth-guard-label">Wachtwoord</label>' +
            '<input id="setup-password" type="password" class="auth-guard-input" placeholder="Voer een sterk wachtwoord in" autocomplete="new-password" />' +
            '<div class="auth-guard-error-message" id="setup-password-error"></div>' +
          '</div>' +

          '<div class="auth-guard-form-group">' +
            '<label for="setup-password-confirm" class="auth-guard-label">Wachtwoord bevestigen</label>' +
            '<input id="setup-password-confirm" type="password" class="auth-guard-input" placeholder="Bevestig het wachtwoord" autocomplete="new-password" />' +
          '</div>' +

          '<div class="auth-guard-requirements">' +
            '<p class="auth-guard-requirements-title">Vereisten:</p>' +
            '<ul class="auth-guard-requirements-list">' +
              '<li data-requirement="length" class="auth-guard-requirement"><span class="auth-guard-requirement-icon">\u25CB</span><span class="auth-guard-requirement-text">Minimaal 12 tekens</span></li>' +
              '<li data-requirement="uppercase" class="auth-guard-requirement"><span class="auth-guard-requirement-icon">\u25CB</span><span class="auth-guard-requirement-text">Minimaal \u00e9\u00e9n hoofdletter (A-Z)</span></li>' +
              '<li data-requirement="lowercase" class="auth-guard-requirement"><span class="auth-guard-requirement-icon">\u25CB</span><span class="auth-guard-requirement-text">Minimaal \u00e9\u00e9n kleine letter (a-z)</span></li>' +
              '<li data-requirement="digit" class="auth-guard-requirement"><span class="auth-guard-requirement-icon">\u25CB</span><span class="auth-guard-requirement-text">Minimaal \u00e9\u00e9n cijfer (0-9)</span></li>' +
              '<li data-requirement="special" class="auth-guard-requirement"><span class="auth-guard-requirement-icon">\u25CB</span><span class="auth-guard-requirement-text">Minimaal \u00e9\u00e9n speciaal teken (!@#$%^&*)</span></li>' +
            '</ul>' +
          '</div>' +

          '<button class="auth-guard-button auth-guard-button-primary" id="setup-next-btn">Volgende</button>' +
          '<div class="auth-guard-error-message" id="setup-step1-error"></div>' +
        '</div>' +

        '<div class="auth-guard-step" data-step="2">' +
          '<h2 class="auth-guard-step-title">Stap 2: Twee-factor authenticatie instellen</h2>' +
          '<p class="auth-guard-step-description">Open uw authenticatie-app (Google Authenticator, Microsoft Authenticator, etc.) en kies <strong>&ldquo;Sleutel handmatig invoeren&rdquo;</strong>.</p>' +

          '<div class="auth-guard-secret-container">' +
            '<div class="auth-guard-secret-field">' +
              '<label class="auth-guard-label">Accountnaam</label>' +
              '<div class="auth-guard-secret-value">' + appName + '</div>' +
            '</div>' +
            '<div class="auth-guard-secret-field">' +
              '<label class="auth-guard-label">Sleutel (geheim)</label>' +
              '<code id="setup-totp-secret" class="auth-guard-secret-key"></code>' +
              '<button type="button" class="auth-guard-copy-btn" id="setup-copy-secret">Kopieer sleutel</button>' +
            '</div>' +
            '<div class="auth-guard-secret-field">' +
              '<label class="auth-guard-label">Type</label>' +
              '<div class="auth-guard-secret-value">Tijdgebaseerd (TOTP)</div>' +
            '</div>' +
          '</div>' +

          '<div class="auth-guard-form-group">' +
            '<label for="setup-totp-code" class="auth-guard-label">Voer de 6-cijferige code in</label>' +
            '<input id="setup-totp-code" type="text" class="auth-guard-input auth-guard-input-code" placeholder="000000" maxlength="6" inputmode="numeric" />' +
            '<div class="auth-guard-error-message" id="setup-totp-error"></div>' +
          '</div>' +

          '<button class="auth-guard-button auth-guard-button-primary" id="setup-activate-btn">Activeren</button>' +
          '<button class="auth-guard-button auth-guard-button-secondary" id="setup-back-btn">Terug</button>' +
          '<div class="auth-guard-error-message" id="setup-step2-error"></div>' +
        '</div>' +
      '</div>' +
    '</div>' +
  '</div>';

  container.innerHTML = setupHtml;

  let setupTotpSecretBuffer = null;
  let setupTotpSecret = null;
  const passwordInput = container.querySelector('#setup-password');
  const passwordConfirmInput = container.querySelector('#setup-password-confirm');
  const nextBtn = container.querySelector('#setup-next-btn');
  const backBtn = container.querySelector('#setup-back-btn');
  const activateBtn = container.querySelector('#setup-activate-btn');
  const totpCodeInput = container.querySelector('#setup-totp-code');

  function updatePasswordRequirements() {
    const password = passwordInput.value;
    const requirements = {
      length: password.length >= AUTH_CONFIG.PASSWORD_MIN_LENGTH,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      digit: /\d/.test(password),
      special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
    };

    Object.entries(requirements).forEach(function(entry) {
      var key = entry[0];
      var met = entry[1];
      var element = container.querySelector('[data-requirement="' + key + '"]');
      if (met) {
        element.classList.add('auth-guard-requirement-met');
        element.querySelector('.auth-guard-requirement-icon').textContent = '\u2713';
      } else {
        element.classList.remove('auth-guard-requirement-met');
        element.querySelector('.auth-guard-requirement-icon').textContent = '\u25CB';
      }
    });

    return requirements;
  }

  passwordInput.addEventListener('input', updatePasswordRequirements);

  nextBtn.addEventListener('click', async function() {
    var errorEl = container.querySelector('#setup-step1-error');
    errorEl.classList.remove('auth-guard-error-show');

    var password = passwordInput.value;
    var passwordConfirm = passwordConfirmInput.value;

    if (password !== passwordConfirm) {
      errorEl.textContent = 'Wachtwoorden komen niet overeen';
      errorEl.classList.add('auth-guard-error-show');
      return;
    }

    var validation = validatePassword(password);
    if (!validation.valid) {
      errorEl.textContent = validation.error;
      errorEl.classList.add('auth-guard-error-show');
      return;
    }

    setupTotpSecretBuffer = await generateTotpSecret();
    setupTotpSecret = bufferToBase32(setupTotpSecretBuffer);
    container.querySelector('#setup-totp-secret').textContent = formatSecretForDisplay(setupTotpSecret);

    var copyBtn = container.querySelector('#setup-copy-secret');
    copyBtn.addEventListener('click', async function() {
      try {
        await navigator.clipboard.writeText(setupTotpSecret);
        copyBtn.textContent = 'Gekopieerd!';
        copyBtn.classList.add('auth-guard-copy-success');
        setTimeout(function() {
          copyBtn.textContent = 'Kopieer sleutel';
          copyBtn.classList.remove('auth-guard-copy-success');
        }, 2000);
      } catch {
        var secretEl = container.querySelector('#setup-totp-secret');
        var range = document.createRange();
        range.selectNodeContents(secretEl);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        copyBtn.textContent = 'Selecteer en kopieer met Ctrl+C';
      }
    });

    container.querySelector('[data-step="1"]').classList.remove('auth-guard-step-active');
    container.querySelector('[data-step="2"]').classList.add('auth-guard-step-active');
  });

  backBtn.addEventListener('click', function() {
    container.querySelector('[data-step="2"]').classList.remove('auth-guard-step-active');
    container.querySelector('[data-step="1"]').classList.add('auth-guard-step-active');
  });

  activateBtn.addEventListener('click', async function() {
    var errorEl = container.querySelector('#setup-step2-error');
    var totpErrorEl = container.querySelector('#setup-totp-error');
    errorEl.classList.remove('auth-guard-error-show');
    totpErrorEl.classList.remove('auth-guard-error-show');

    var totpCode = totpCodeInput.value.trim();

    if (totpCode.length !== AUTH_CONFIG.TOTP_DIGITS) {
      totpErrorEl.textContent = 'Voer een ' + AUTH_CONFIG.TOTP_DIGITS + '-cijferige code in';
      totpErrorEl.classList.add('auth-guard-error-show');
      return;
    }

    var isValid = await verifyTotpCode(setupTotpSecretBuffer, totpCode);
    if (!isValid) {
      totpErrorEl.textContent = 'Ongeldige code. Controleer uw authenticatie-app.';
      totpErrorEl.classList.add('auth-guard-error-show');
      return;
    }

    try {
      nextBtn.disabled = true;
      activateBtn.disabled = true;

      var password = passwordInput.value;
      var passwordConfig = await hashPassword(password);
      var encryptedTotp = await encryptTotpSecret(setupTotpSecretBuffer, password);

      localStorage.setItem(AUTH_CONFIG.STORAGE_KEY_CONFIG, JSON.stringify(passwordConfig));
      localStorage.setItem(AUTH_CONFIG.STORAGE_KEY_TOTP, JSON.stringify(encryptedTotp));

      createSession();
      onSuccess();
    } catch (error) {
      errorEl.textContent = 'Fout bij setup: ' + error.message;
      errorEl.classList.add('auth-guard-error-show');
      nextBtn.disabled = false;
      activateBtn.disabled = false;
    }
  });

  totpCodeInput.addEventListener('input', function(e) {
    e.target.value = e.target.value.replace(/[^\d]/g, '');
  });
}

// ============================================================================
// LOGIN-SCHERM (TERUGKEREND GEBRUIK)
// ============================================================================

function renderLoginScreen(container, onSuccess) {
  var appName = escapeHtml(AUTH_CONFIG.APP_NAME);
  var loginHtml = '<div class="auth-guard-container auth-guard-login">' +
    '<div class="auth-guard-card">' +
      '<div class="auth-guard-header">' +
        '<div class="auth-guard-logo">' +
          '<svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">' +
            '<rect width="48" height="48" rx="12" fill="var(--color-primary, #0066cc)" opacity="0.1"/>' +
            '<path d="M24 12L14 18V30L24 36L34 30V18L24 12Z" stroke="var(--color-primary, #0066cc)" stroke-width="2" fill="none"/>' +
            '<path d="M24 20V28M20 24H28" stroke="var(--color-primary, #0066cc)" stroke-width="2" stroke-linecap="round"/>' +
          '</svg>' +
        '</div>' +
        '<h1 class="auth-guard-title">' + appName + '</h1>' +
        '<p class="auth-guard-subtitle">Inloggen</p>' +
        '<p class="auth-guard-org">Knowledge by Data B.V.</p>' +
      '</div>' +

      '<div class="auth-guard-content">' +
        '<div class="auth-guard-form-group">' +
          '<label for="login-password" class="auth-guard-label">Wachtwoord</label>' +
          '<input id="login-password" type="password" class="auth-guard-input" placeholder="Voer uw wachtwoord in" autocomplete="current-password" />' +
        '</div>' +

        '<div class="auth-guard-form-group">' +
          '<label for="login-totp" class="auth-guard-label">2FA Code (van uw authenticatie-app)</label>' +
          '<input id="login-totp" type="text" class="auth-guard-input auth-guard-input-code" placeholder="000000" maxlength="6" inputmode="numeric" />' +
        '</div>' +

        '<div class="auth-guard-lockout-message" id="login-lockout" style="display: none;">' +
          '<strong>Te veel inlogpogingen.</strong><br />' +
          'Probeer het over <span id="login-lockout-seconds">0</span> seconde opnieuw.' +
        '</div>' +

        '<button class="auth-guard-button auth-guard-button-primary" id="login-btn">Inloggen</button>' +
        '<div class="auth-guard-error-message" id="login-error"></div>' +
      '</div>' +
    '</div>' +
  '</div>';

  container.innerHTML = loginHtml;

  var passwordInput = container.querySelector('#login-password');
  var totpInput = container.querySelector('#login-totp');
  var loginBtn = container.querySelector('#login-btn');
  var errorEl = container.querySelector('#login-error');
  var lockoutEl = container.querySelector('#login-lockout');
  var lockoutSecondsEl = container.querySelector('#login-lockout-seconds');

  totpInput.addEventListener('input', function(e) {
    e.target.value = e.target.value.replace(/[^\d]/g, '');
  });

  function checkBruteForceStatus() {
    var attemptsData = sessionStorage.getItem(AUTH_CONFIG.STORAGE_KEY_ATTEMPTS);
    if (!attemptsData) return { locked: false };

    try {
      var attempts = JSON.parse(attemptsData);
      var now = Date.now();
      var backoffDuration = getBackoffDuration(attempts.count);
      var timeRemaining = attempts.lastAttemptTime + backoffDuration - now;

      if (timeRemaining > 0) {
        return { locked: true, timeRemaining: timeRemaining };
      } else {
        return { locked: false };
      }
    } catch {
      return { locked: false };
    }
  }

  function updateBruteForceUI() {
    var status = checkBruteForceStatus();
    if (status.locked) {
      lockoutEl.style.display = 'block';
      loginBtn.disabled = true;
      passwordInput.disabled = true;
      totpInput.disabled = true;

      var updateCountdown = function() {
        var status = checkBruteForceStatus();
        if (status.locked) {
          var seconds = Math.ceil(status.timeRemaining / 1000);
          lockoutSecondsEl.textContent = seconds;
          setTimeout(updateCountdown, 100);
        } else {
          lockoutEl.style.display = 'none';
          loginBtn.disabled = false;
          passwordInput.disabled = false;
          totpInput.disabled = false;
          passwordInput.focus();
        }
      };

      updateCountdown();
    } else {
      lockoutEl.style.display = 'none';
      loginBtn.disabled = false;
      passwordInput.disabled = false;
      totpInput.disabled = false;
      passwordInput.focus();
    }
  }

  updateBruteForceUI();

  loginBtn.addEventListener('click', async function() {
    errorEl.classList.remove('auth-guard-error-show');

    var status = checkBruteForceStatus();
    if (status.locked) {
      return;
    }

    var password = passwordInput.value;
    var totpCode = totpInput.value.trim();

    if (!password || totpCode.length !== AUTH_CONFIG.TOTP_DIGITS) {
      errorEl.textContent = 'Vul beide velden in';
      errorEl.classList.add('auth-guard-error-show');
      return;
    }

    try {
      loginBtn.disabled = true;

      var configData = localStorage.getItem(AUTH_CONFIG.STORAGE_KEY_CONFIG);
      var encryptedTotpData = localStorage.getItem(AUTH_CONFIG.STORAGE_KEY_TOTP);

      if (!configData || !encryptedTotpData) {
        errorEl.textContent = 'Configuratiegegevens niet gevonden';
        errorEl.classList.add('auth-guard-error-show');
        loginBtn.disabled = false;
        return;
      }

      var config = JSON.parse(configData);
      var encryptedTotp = JSON.parse(encryptedTotpData);

      var passwordValid = await verifyPassword(password, config);
      if (!passwordValid) {
        recordFailedAttempt();
        errorEl.textContent = 'Wachtwoord onjuist';
        errorEl.classList.add('auth-guard-error-show');
        loginBtn.disabled = false;
        updateBruteForceUI();
        return;
      }

      var totpSecretBuffer = await decryptTotpSecret(encryptedTotp, password);
      var totpValid = await verifyTotpCode(totpSecretBuffer, totpCode);

      if (!totpValid) {
        recordFailedAttempt();
        errorEl.textContent = 'Ongeldige 2FA-code';
        errorEl.classList.add('auth-guard-error-show');
        loginBtn.disabled = false;
        updateBruteForceUI();
        return;
      }

      sessionStorage.removeItem(AUTH_CONFIG.STORAGE_KEY_ATTEMPTS);
      createSession();
      onSuccess();
    } catch (error) {
      recordFailedAttempt();
      errorEl.textContent = 'Inlogfout: ' + error.message;
      errorEl.classList.add('auth-guard-error-show');
      loginBtn.disabled = false;
      updateBruteForceUI();
    }
  });

  [passwordInput, totpInput].forEach(function(input) {
    input.addEventListener('keypress', function(e) {
      if (e.key === 'Enter' && !loginBtn.disabled) {
        loginBtn.click();
      }
    });
  });
}

// ============================================================================
// CSS — Inline zodat auth-guard.js volledig standalone is
// ============================================================================

(function injectAuthGuardStyles() {
  if (document.getElementById('auth-guard-styles')) return;
  var style = document.createElement('style');
  style.id = 'auth-guard-styles';
  style.textContent = [
    '.auth-guard-container { font-family: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--color-text, #1e293b); background: var(--color-bg, #f8fafc); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; position: fixed; top: 0; left: 0; right: 0; bottom: 0; z-index: 99999; }',
    '.auth-guard-card { background: var(--color-surface, #ffffff); border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.12); width: 100%; max-width: 480px; padding: 40px; }',
    '.auth-guard-header { text-align: center; margin-bottom: 32px; }',
    '.auth-guard-logo { margin-bottom: 16px; }',
    '.auth-guard-title { margin: 0 0 4px 0; font-size: 24px; font-weight: 600; color: var(--color-text, #1e293b); }',
    '.auth-guard-subtitle { margin: 0; font-size: 15px; color: var(--color-text-muted, #64748b); }',
    '.auth-guard-org { margin: 8px 0 0 0; font-size: 12px; color: var(--color-text-dim, #94a3b8); letter-spacing: 0.5px; text-transform: uppercase; }',
    '.auth-guard-step { display: none; }',
    '.auth-guard-step-active { display: block; }',
    '.auth-guard-step-title { margin: 0 0 8px 0; font-size: 17px; font-weight: 600; color: var(--color-text, #1e293b); }',
    '.auth-guard-step-description { margin: 0 0 20px 0; font-size: 14px; color: var(--color-text-muted, #64748b); line-height: 1.6; }',
    '.auth-guard-form-group { margin-bottom: 20px; }',
    '.auth-guard-label { display: block; margin-bottom: 6px; font-size: 13px; font-weight: 500; color: var(--color-text, #1e293b); }',
    '.auth-guard-input { width: 100%; padding: 10px 12px; font-size: 14px; border: 2px solid var(--color-border, #e2e8f0); border-radius: 6px; background: var(--color-surface, #ffffff); color: var(--color-text, #1e293b); box-sizing: border-box; transition: border-color 0.2s; outline: none; }',
    '.auth-guard-input:focus { border-color: var(--color-primary, #3b82f6); }',
    '.auth-guard-input-code { font-size: 20px; letter-spacing: 4px; text-align: center; font-family: "Courier New", monospace; font-weight: 600; }',
    '.auth-guard-requirements { background: var(--color-surface-alt, #f1f5f9); border: 1px solid var(--color-border, #e2e8f0); border-radius: 6px; padding: 16px; margin-bottom: 20px; }',
    '.auth-guard-requirements-title { margin: 0 0 10px 0; font-size: 13px; font-weight: 600; color: var(--color-text, #1e293b); }',
    '.auth-guard-requirements-list { list-style: none; margin: 0; padding: 0; }',
    '.auth-guard-requirement { display: flex; align-items: center; padding: 4px 0; font-size: 13px; color: var(--color-text-muted, #64748b); transition: color 0.2s; }',
    '.auth-guard-requirement-icon { display: inline-flex; align-items: center; justify-content: center; width: 20px; margin-right: 8px; font-weight: bold; }',
    '.auth-guard-requirement.auth-guard-requirement-met { color: #16a34a; }',
    '.auth-guard-requirement.auth-guard-requirement-met .auth-guard-requirement-icon { color: #16a34a; }',
    '.auth-guard-secret-container { background: var(--color-surface-alt, #f1f5f9); border: 2px solid var(--color-primary, #3b82f6); border-radius: 8px; padding: 20px; margin-bottom: 20px; }',
    '.auth-guard-secret-field { margin-bottom: 14px; }',
    '.auth-guard-secret-field:last-child { margin-bottom: 0; }',
    '.auth-guard-secret-value { font-size: 14px; color: var(--color-text, #1e293b); font-weight: 500; }',
    '.auth-guard-secret-key { display: block; padding: 12px; background: var(--color-surface, #ffffff); border: 1px solid var(--color-border, #e2e8f0); border-radius: 6px; font-family: "Courier New", monospace; font-size: 15px; font-weight: 700; letter-spacing: 2px; word-break: break-all; text-align: center; color: var(--color-text, #1e293b); margin-bottom: 8px; user-select: all; }',
    '.auth-guard-copy-btn { display: block; width: 100%; padding: 8px; font-size: 13px; font-weight: 500; color: var(--color-primary, #3b82f6); background: transparent; border: 1px solid var(--color-primary, #3b82f6); border-radius: 4px; cursor: pointer; transition: all 0.2s; }',
    '.auth-guard-copy-btn:hover { background: var(--color-primary, #3b82f6); color: white; }',
    '.auth-guard-copy-btn.auth-guard-copy-success { background: #16a34a; border-color: #16a34a; color: white; }',
    '.auth-guard-button { width: 100%; padding: 12px; font-size: 14px; font-weight: 600; border: none; border-radius: 6px; cursor: pointer; transition: all 0.2s; margin-bottom: 10px; }',
    '.auth-guard-button-primary { background: var(--color-primary, #3b82f6); color: white; }',
    '.auth-guard-button-primary:hover { background: var(--color-primary-hover, #2563eb); }',
    '.auth-guard-button-primary:disabled { background: #94a3b8; cursor: not-allowed; }',
    '.auth-guard-button-secondary { background: var(--color-surface-alt, #e2e8f0); color: var(--color-text, #1e293b); }',
    '.auth-guard-button-secondary:hover { background: #cbd5e1; }',
    '.auth-guard-error-message { font-size: 13px; color: #dc2626; margin-top: 8px; display: none; }',
    '.auth-guard-error-message.auth-guard-error-show { display: block; }',
    '.auth-guard-lockout-message { background: #fef3c7; border: 1px solid #f59e0b; color: #92400e; padding: 12px; border-radius: 6px; font-size: 13px; margin-bottom: 12px; line-height: 1.6; }',
  ].join('\n');
  document.head.appendChild(style);
})();

// ============================================================================
// PUBLIC API
// ============================================================================

var AuthGuard = {
  isConfigured: function() {
    var configData = localStorage.getItem(AUTH_CONFIG.STORAGE_KEY_CONFIG);
    var totpData = localStorage.getItem(AUTH_CONFIG.STORAGE_KEY_TOTP);
    return !!(configData && totpData);
  },

  isAuthenticated: function() {
    return !!getSession();
  },

  showAuthScreen: function(containerEl, onSuccess) {
    if (typeof containerEl !== 'object' || !containerEl) {
      throw new Error('containerEl moet een geldig DOM-element zijn');
    }
    if (typeof onSuccess !== 'function') {
      throw new Error('onSuccess moet een function zijn');
    }

    if (this.isConfigured()) {
      renderLoginScreen(containerEl, onSuccess);
    } else {
      renderSetupScreen(containerEl, onSuccess);
    }
  },

  protect: function(onReady) {
    if (this.isAuthenticated()) {
      onReady();
      return;
    }

    var overlay = document.getElementById('authOverlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'authOverlay';
      document.body.insertBefore(overlay, document.body.firstChild);
    }

    var appContent = document.getElementById('appContent');
    if (appContent) {
      appContent.style.display = 'none';
    }

    overlay.style.display = 'block';

    this.showAuthScreen(overlay, function() {
      overlay.style.display = 'none';
      overlay.innerHTML = '';
      if (appContent) {
        appContent.style.display = '';
      }
      onReady();
    });
  },

  logout: function() {
    sessionStorage.removeItem(AUTH_CONFIG.STORAGE_KEY_SESSION);
    sessionStorage.removeItem(AUTH_CONFIG.STORAGE_KEY_ATTEMPTS);
  },

  resetAll: function() {
    localStorage.removeItem(AUTH_CONFIG.STORAGE_KEY_CONFIG);
    localStorage.removeItem(AUTH_CONFIG.STORAGE_KEY_TOTP);
    sessionStorage.removeItem(AUTH_CONFIG.STORAGE_KEY_SESSION);
    sessionStorage.removeItem(AUTH_CONFIG.STORAGE_KEY_ATTEMPTS);
  },
};

window.AuthGuard = AuthGuard;

if (typeof module !== 'undefined' && module.exports) {
  module.exports = AuthGuard;
}
