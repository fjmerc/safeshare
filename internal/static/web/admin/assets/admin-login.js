// ============================================
// WebAuthn Helper Functions
// ============================================
function base64URLEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ============================================
// MFA State Variables
// ============================================
let mfaChallengeId = null;
let mfaExpiresAt = null;
let mfaTimerInterval = null;
let mfaAvailableMethods = [];

// DOM elements
const loginForm = document.getElementById('loginForm');
const mfaSection = document.getElementById('mfaSection');
const totpForm = document.getElementById('totpForm');
const recoveryForm = document.getElementById('recoveryForm');
const mfaMethods = document.getElementById('mfaMethods');
const mfaBackBtn = document.getElementById('mfaBackBtn');
const useRecoveryBtn = document.getElementById('useRecoveryBtn');
const useTotpBtn = document.getElementById('useTotpBtn');
const mfaTimeLeft = document.getElementById('mfaTimeLeft');
const mfaTimer = document.getElementById('mfaTimer');

// ============================================
// MFA Functions
// ============================================
function showMFASection(data) {
    // Store challenge info
    mfaChallengeId = data.challenge_id;
    mfaExpiresAt = Date.now() + (data.expires_in * 1000);
    mfaAvailableMethods = data.available_methods || ['totp'];

    // Hide login form
    loginForm.style.display = 'none';

    // Show MFA section
    mfaSection.style.display = 'block';

    // Show/hide recovery option based on available methods
    if (mfaAvailableMethods.includes('recovery')) {
        mfaMethods.style.display = 'block';
    } else {
        mfaMethods.style.display = 'none';
    }

    // Show/hide WebAuthn option based on available methods
    const useWebAuthnBtn = document.getElementById('useWebAuthnBtn');
    const useWebAuthnFromRecoveryBtn = document.getElementById('useWebAuthnFromRecoveryBtn');
    if (mfaAvailableMethods.includes('webauthn')) {
        useWebAuthnBtn.style.display = 'block';
        useWebAuthnFromRecoveryBtn.style.display = 'block';
    } else {
        useWebAuthnBtn.style.display = 'none';
        useWebAuthnFromRecoveryBtn.style.display = 'none';
    }

    // Reset forms
    document.getElementById('totpCode').value = '';
    document.getElementById('recoveryCode').value = '';
    totpForm.style.display = 'block';
    recoveryForm.style.display = 'none';

    // Auto-focus TOTP input
    setTimeout(() => {
        document.getElementById('totpCode').focus();
    }, 100);

    // Start countdown timer
    startMFATimer();
}

function resetToLogin() {
    // Clear MFA state
    mfaChallengeId = null;
    mfaExpiresAt = null;
    mfaAvailableMethods = [];
    if (mfaTimerInterval) {
        clearInterval(mfaTimerInterval);
        mfaTimerInterval = null;
    }

    // Hide MFA section
    mfaSection.style.display = 'none';

    // Show login form
    loginForm.style.display = 'block';

    // Clear password field for security
    document.getElementById('password').value = '';

    // Re-enable login button
    const submitBtn = loginForm.querySelector('button[type="submit"]');
    submitBtn.disabled = false;
    submitBtn.textContent = 'Login';
}

function startMFATimer() {
    if (mfaTimerInterval) {
        clearInterval(mfaTimerInterval);
    }

    function updateTimer() {
        const remaining = Math.max(0, mfaExpiresAt - Date.now());
        const seconds = Math.floor(remaining / 1000);
        const minutes = Math.floor(seconds / 60);
        const secs = seconds % 60;

        mfaTimeLeft.textContent = `${minutes}:${secs.toString().padStart(2, '0')}`;

        // Add warning style when less than 60 seconds
        if (seconds < 60) {
            mfaTimer.classList.add('expiring');
        } else {
            mfaTimer.classList.remove('expiring');
        }

        // Handle expiry
        if (remaining <= 0) {
            clearInterval(mfaTimerInterval);
            showToast('MFA session expired. Please log in again.', 'error');
            resetToLogin();
        }
    }

    updateTimer();
    mfaTimerInterval = setInterval(updateTimer, 1000);
}

async function verifyMFA(code, isRecovery = false) {
    const verifyBtn = isRecovery
        ? document.getElementById('recoveryVerifyBtn')
        : document.getElementById('mfaVerifyBtn');

    const originalText = verifyBtn.textContent;
    verifyBtn.disabled = true;
    verifyBtn.textContent = 'Verifying...';

    try {
        const response = await fetch('/api/auth/mfa/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                challenge_id: mfaChallengeId,
                code: code,
                is_recovery: isRecovery
            }),
            credentials: 'include',
        });

        const data = await response.json();

        if (response.ok) {
            // Clear timer
            if (mfaTimerInterval) {
                clearInterval(mfaTimerInterval);
            }

            // Store CSRF token if provided
            if (data.csrf_token) {
                sessionStorage.setItem('csrf_token', data.csrf_token);
            }

            showToast('Verification successful! Redirecting...', 'success');

            // Redirect to admin dashboard
            setTimeout(() => {
                window.location.href = '/admin/dashboard';
            }, 1000);
        } else {
            showToast(data.error || 'Verification failed. Please try again.', 'error');
            verifyBtn.disabled = false;
            verifyBtn.textContent = originalText;

            // Clear the input on failure
            if (isRecovery) {
                document.getElementById('recoveryCode').value = '';
                document.getElementById('recoveryCode').focus();
            } else {
                document.getElementById('totpCode').value = '';
                document.getElementById('totpCode').focus();
            }
        }
    } catch (error) {
        console.error('MFA verification error:', error);
        showToast('Network error. Please try again.', 'error');
        verifyBtn.disabled = false;
        verifyBtn.textContent = originalText;
    }
}

// ============================================
// WebAuthn Authentication
// ============================================
async function authenticateWithWebAuthn() {
    // Check if WebAuthn is supported
    if (!window.PublicKeyCredential) {
        showToast('Your browser does not support security keys', 'error');
        return;
    }

    const webauthnBtn = document.getElementById('useWebAuthnBtn');
    const originalText = webauthnBtn.textContent;
    webauthnBtn.disabled = true;
    webauthnBtn.textContent = 'Authenticating...';

    try {
        // Step 1: Begin WebAuthn authentication
        const beginResponse = await fetch('/api/auth/mfa/webauthn/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                challenge_id: mfaChallengeId
            }),
            credentials: 'include',
        });

        if (!beginResponse.ok) {
            const errorData = await beginResponse.json();
            throw new Error(errorData.error || 'Failed to start authentication');
        }

        const beginData = await beginResponse.json();
        const options = beginData.options;

        // Convert challenge and allowCredentials from base64url
        options.publicKey.challenge = base64URLDecode(options.publicKey.challenge);
        if (options.publicKey.allowCredentials) {
            options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(cred => ({
                ...cred,
                id: base64URLDecode(cred.id)
            }));
        }

        // Step 2: Get credential from authenticator
        webauthnBtn.textContent = 'Touch your security key...';
        const credential = await navigator.credentials.get(options);

        // Step 3: Finish WebAuthn authentication
        const credentialData = {
            id: credential.id,
            rawId: base64URLEncode(credential.rawId),
            type: credential.type,
            response: {
                authenticatorData: base64URLEncode(credential.response.authenticatorData),
                clientDataJSON: base64URLEncode(credential.response.clientDataJSON),
                signature: base64URLEncode(credential.response.signature)
            }
        };

        // Include userHandle if present
        if (credential.response.userHandle) {
            credentialData.response.userHandle = base64URLEncode(credential.response.userHandle);
        }

        const finishResponse = await fetch('/api/auth/mfa/webauthn/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                challenge_id: mfaChallengeId,
                credential: credentialData
            }),
            credentials: 'include',
        });

        const finishData = await finishResponse.json();

        if (finishResponse.ok) {
            // Clear timer
            if (mfaTimerInterval) {
                clearInterval(mfaTimerInterval);
            }

            // Store CSRF token if provided
            if (finishData.csrf_token) {
                sessionStorage.setItem('csrf_token', finishData.csrf_token);
            }

            showToast('Authentication successful! Redirecting...', 'success');

            // Redirect to admin dashboard
            setTimeout(() => {
                window.location.href = '/admin/dashboard';
            }, 1000);
        } else {
            throw new Error(finishData.error || 'Authentication failed');
        }

    } catch (error) {
        console.error('WebAuthn authentication error:', error);

        // Handle user cancellation gracefully
        if (error.name === 'NotAllowedError') {
            showToast('Authentication cancelled or timed out', 'error');
        } else {
            showToast(error.message || 'Authentication failed. Please try again.', 'error');
        }

        webauthnBtn.disabled = false;
        webauthnBtn.textContent = originalText;
    }
}

// WebAuthn button event handlers
document.getElementById('useWebAuthnBtn').addEventListener('click', authenticateWithWebAuthn);
document.getElementById('useWebAuthnFromRecoveryBtn').addEventListener('click', authenticateWithWebAuthn);

// ============================================
// Event Handlers
// ============================================

// Handle login form submission
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');

    // Disable button and show loading state
    submitBtn.disabled = true;
    submitBtn.textContent = 'Logging in...';

    try {
        const response = await fetch('/admin/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                username: username,
                password: password
            })
        });

        const data = await response.json();

        if (response.ok) {
            // Check if MFA is required
            if (data.mfa_required) {
                showMFASection(data);
                return;
            }

            if (data.success) {
                // Store CSRF token
                if (data.csrf_token) {
                    sessionStorage.setItem('csrf_token', data.csrf_token);
                }
                // Show success toast
                showToast('Login successful! Redirecting...', 'success');

                // Redirect to dashboard after brief delay
                setTimeout(() => {
                    window.location.href = '/admin/dashboard';
                }, 1000);
            }
        } else {
            showToast(data.error || 'Login failed. Please try again.', 'error');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Login';
        }
    } catch (error) {
        console.error('Login error:', error);
        showToast('Network error. Please try again.', 'error');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Login';
    }
});

// TOTP form submission
document.getElementById('mfaTotpForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = document.getElementById('totpCode').value.trim();

    // Validate 6 digits
    if (!/^\d{6}$/.test(code)) {
        showToast('Please enter a 6-digit code', 'error');
        return;
    }

    await verifyMFA(code, false);
});

// Recovery code form submission
document.getElementById('mfaRecoveryForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = document.getElementById('recoveryCode').value.trim().toUpperCase();

    // Basic format validation
    if (code.length < 10) {
        showToast('Please enter a valid recovery code', 'error');
        return;
    }

    await verifyMFA(code, true);
});

// Back to login button
mfaBackBtn.addEventListener('click', () => {
    resetToLogin();
});

// Switch to recovery code form
useRecoveryBtn.addEventListener('click', () => {
    totpForm.style.display = 'none';
    recoveryForm.style.display = 'block';
    document.getElementById('recoveryCode').focus();
});

// Switch to TOTP form
useTotpBtn.addEventListener('click', () => {
    recoveryForm.style.display = 'none';
    totpForm.style.display = 'block';
    document.getElementById('totpCode').focus();
});

// Auto-format TOTP input (digits only)
document.getElementById('totpCode').addEventListener('input', (e) => {
    e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
});

// Auto-format recovery code input
document.getElementById('recoveryCode').addEventListener('input', (e) => {
    // Remove non-alphanumeric except dashes
    let value = e.target.value.toUpperCase().replace(/[^A-Z0-9-]/g, '');
    e.target.value = value;
});
