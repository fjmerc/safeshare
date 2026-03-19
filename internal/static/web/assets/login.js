// Load theme preference from localStorage
(function() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
})();

// Theme toggle functionality
const themeToggle = document.getElementById('themeToggle');
if (themeToggle) {
    themeToggle.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);

        // Toggle icon visibility
        const sunIcon = themeToggle.querySelector('.theme-icon-sun');
        const moonIcon = themeToggle.querySelector('.theme-icon-moon');

        if (newTheme === 'dark') {
            sunIcon.style.display = 'none';
            moonIcon.style.display = 'block';
        } else {
            sunIcon.style.display = 'block';
            moonIcon.style.display = 'none';
        }
    });

    // Set initial icon based on current theme
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const sunIcon = themeToggle.querySelector('.theme-icon-sun');
    const moonIcon = themeToggle.querySelector('.theme-icon-moon');

    if (currentTheme === 'dark') {
        sunIcon.style.display = 'none';
        moonIcon.style.display = 'block';
    } else {
        sunIcon.style.display = 'block';
        moonIcon.style.display = 'none';
    }
}

// Universal password toggle handler
document.querySelectorAll('[data-password-toggle]').forEach(button => {
    button.addEventListener('click', () => {
        const targetId = button.getAttribute('data-password-toggle');
        const passwordInput = document.getElementById(targetId);
        const eyeIcon = button.querySelector('.eye-icon');
        const eyeOffIcon = button.querySelector('.eye-off-icon');

        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            if (eyeIcon && eyeOffIcon) {
                eyeIcon.style.display = 'none';
                eyeOffIcon.style.display = 'block';
            }
        } else {
            passwordInput.type = 'password';
            if (eyeIcon && eyeOffIcon) {
                eyeIcon.style.display = 'block';
                eyeOffIcon.style.display = 'none';
            }
        }
    });
});

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
// MFA Verification Logic
// ============================================
let mfaChallengeId = null;
let mfaExpiresAt = null;
let mfaTimerInterval = null;
let mfaAvailableMethods = [];

// DOM elements for MFA
const mfaSection = document.getElementById('mfaSection');
const totpForm = document.getElementById('totpForm');
const recoveryForm = document.getElementById('recoveryForm');
const mfaMethods = document.getElementById('mfaMethods');
const mfaBackBtn = document.getElementById('mfaBackBtn');
const useRecoveryBtn = document.getElementById('useRecoveryBtn');
const useTotpBtn = document.getElementById('useTotpBtn');
const mfaTimeLeft = document.getElementById('mfaTimeLeft');
const mfaTimer = document.getElementById('mfaTimer');

function showMFASection(data) {
    // Store challenge info
    mfaChallengeId = data.challenge_id;
    mfaExpiresAt = Date.now() + (data.expires_in * 1000);
    mfaAvailableMethods = data.available_methods || ['totp'];

    // Hide login form and SSO section
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('ssoSection').style.display = 'none';

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

    // Re-enable login button for potential retry
    loginBtn.disabled = false;
    loginBtn.textContent = 'Sign In';
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
    document.getElementById('loginForm').style.display = 'block';

    // Re-load SSO providers (they may have been hidden)
    loadSSOProviders();

    // Clear password field for security
    document.getElementById('password').value = '';
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

            showToast('Verification successful! Redirecting...', 'success');

            // Check if password change is required
            if (data.require_password_change) {
                setTimeout(() => {
                    window.location.href = '/dashboard?change_password=true';
                }, 1000);
            } else {
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            }
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

// WebAuthn authentication function
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

            showToast('Authentication successful! Redirecting...', 'success');

            // Check if password change is required
            if (finishData.require_password_change) {
                setTimeout(() => {
                    window.location.href = '/dashboard?change_password=true';
                }, 1000);
            } else {
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            }
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

// ============================================
// End MFA Logic
// ============================================

const loginForm = document.getElementById('loginForm');
const loginBtn = document.getElementById('loginBtn');

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Disable button and show loading state
    loginBtn.disabled = true;
    loginBtn.textContent = 'Signing in...';

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
            credentials: 'include', // Important for cookies
        });

        const data = await response.json();

        if (response.ok) {
            // Check if MFA is required
            if (data.mfa_required) {
                showMFASection(data);
                return;
            }

            // Show success toast
            showToast('Login successful! Redirecting...', 'success');

            // Check if password change is required
            if (data.require_password_change) {
                // Redirect to dashboard where they'll be prompted to change password
                setTimeout(() => {
                    window.location.href = '/dashboard?change_password=true';
                }, 1000);
            } else {
                // Normal login - redirect to dashboard
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            }
        } else {
            // Show error toast
            showToast(data.error || 'Login failed. Please try again.', 'error');

            // Re-enable button
            loginBtn.disabled = false;
            loginBtn.textContent = 'Sign In';
        }
    } catch (error) {
        console.error('Login error:', error);
        showToast('Network error. Please check your connection and try again.', 'error');

        // Re-enable button
        loginBtn.disabled = false;
        loginBtn.textContent = 'Sign In';
    }
});

// Check if already logged in
async function checkAuth() {
    try {
        const response = await fetch('/api/auth/user', {
            credentials: 'include'
        });

        if (response.ok) {
            // Already logged in, redirect to dashboard
            window.location.href = '/dashboard';
        }
    } catch (error) {
        // Not logged in, stay on login page
        console.log('Not logged in');
    }
}

checkAuth();

// SSO Login Support
const ssoSection = document.getElementById('ssoSection');
const ssoProviders = document.getElementById('ssoProviders');

// Check for SSO error in URL parameters
function handleSSOError() {
    const urlParams = new URLSearchParams(window.location.search);
    const errorCode = urlParams.get('error');
    const errorMessage = urlParams.get('message');

    if (errorCode) {
        // Map error codes to user-friendly messages
        const errorMessages = {
            'sso_failed': 'SSO authentication failed',
            'missing_code': 'Authorization code missing',
            'missing_state': 'Security validation failed',
            'invalid_provider': 'Invalid SSO provider',
            'provider_error': 'SSO provider error',
            'token_exchange_failed': 'Failed to complete authentication',
            'userinfo_failed': 'Failed to retrieve user information',
            'domain_not_allowed': 'Your email domain is not allowed',
            'auth_failed': 'Authentication failed',
            'account_disabled': 'Your account has been disabled'
        };

        const displayMessage = errorMessages[errorCode] || errorMessage || 'SSO login failed';
        showToast(displayMessage, 'error');

        // Clear URL parameters to prevent showing error on refresh
        window.history.replaceState({}, document.title, window.location.pathname);
    }
}

// Load SSO providers
async function loadSSOProviders() {
    try {
        const response = await fetch('/api/auth/sso/providers');
        if (!response.ok) {
            console.log('SSO providers endpoint not available');
            return;
        }

        const data = await response.json();

        // Only show SSO section if SSO is enabled and there are providers
        if (!data.enabled || !data.providers || data.providers.length === 0) {
            return;
        }

        // Show SSO section
        ssoSection.style.display = 'block';

        // Create buttons for each provider
        data.providers.forEach(provider => {
            const button = createSSOButton(provider);
            ssoProviders.appendChild(button);
        });

    } catch (error) {
        console.log('Failed to load SSO providers:', error);
        // Silently fail - SSO is optional
    }
}

// Create SSO button element
function createSSOButton(provider) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'sso-btn';
    button.setAttribute('data-provider', provider.slug);

    // Apply custom colors if provided
    if (provider.button_color) {
        button.style.backgroundColor = provider.button_color;
        button.style.borderColor = provider.button_color;
    }
    if (provider.button_text_color) {
        button.style.color = provider.button_text_color;
    }

    // Create icon element
    let iconHTML = '';
    if (provider.icon_url) {
        iconHTML = `<img src="${escapeHTML(provider.icon_url)}" alt="" aria-hidden="true">`;
    } else {
        // Default SSO icon
        iconHTML = `
            <span class="sso-icon-placeholder">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                    <circle cx="12" cy="16" r="1"></circle>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
            </span>
        `;
    }

    button.innerHTML = `${iconHTML}<span>Continue with ${escapeHTML(provider.name)}</span>`;

    // Hide broken icon images (CSP blocks inline onerror handlers)
    var img = button.querySelector('img');
    if (img) {
        img.addEventListener('error', function() { this.style.display = 'none'; });
    }

    // Handle click
    button.addEventListener('click', () => handleSSOLogin(provider.slug, button));

    return button;
}

// Handle SSO login button click
async function handleSSOLogin(providerSlug, button) {
    // Disable button and show loading state
    const originalContent = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span>Redirecting...</span>`;

    try {
        // Build login URL with return path
        const returnUrl = encodeURIComponent('/dashboard');
        const loginUrl = `/api/auth/sso/${providerSlug}/login?return_url=${returnUrl}`;

        // Redirect to SSO login endpoint
        window.location.href = loginUrl;
    } catch (error) {
        console.error('SSO login error:', error);
        showToast('Failed to initiate SSO login', 'error');

        // Re-enable button
        button.disabled = false;
        button.innerHTML = originalContent;
    }
}

// HTML escape helper to prevent XSS
function escapeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Initialize SSO
handleSSOError();
loadSSOProviders();
