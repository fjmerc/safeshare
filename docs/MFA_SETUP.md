# Multi-Factor Authentication (MFA) Setup Guide

SafeShare supports Multi-Factor Authentication (MFA) to add an extra layer of security to user accounts. This guide covers setup, configuration, and management of MFA for both users and administrators.

## Table of Contents

- [Overview](#overview)
- [Supported MFA Methods](#supported-mfa-methods)
- [Server Configuration](#server-configuration)
- [User Setup Guide](#user-setup-guide)
  - [Setting up TOTP](#setting-up-totp)
  - [Setting up WebAuthn](#setting-up-webauthn)
  - [Recovery Codes](#recovery-codes)
- [Login with MFA](#login-with-mfa)
- [Managing MFA](#managing-mfa)
- [Admin MFA Management](#admin-mfa-management)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Overview

MFA provides an additional security layer beyond username and password authentication. When enabled, users must provide a second factor (TOTP code or hardware key) after entering their credentials.

**Key Features:**
- Time-based One-Time Password (TOTP) support
- WebAuthn/FIDO2 hardware key support (YubiKey, etc.)
- Backup recovery codes for account recovery
- Admin ability to reset user MFA
- Configurable challenge expiry times
- Timing attack protection

---

## Supported MFA Methods

### TOTP (Time-based One-Time Password)

TOTP generates 6-digit codes that change every 30 seconds. Compatible with any authenticator app:

**Recommended Apps:**
- **Google Authenticator** (iOS, Android)
- **Microsoft Authenticator** (iOS, Android)
- **Authy** (iOS, Android, Desktop)
- **1Password** (iOS, Android, Desktop)
- **Bitwarden** (iOS, Android, Desktop)

### WebAuthn/FIDO2 (Hardware Keys)

WebAuthn provides phishing-resistant authentication using hardware security keys:

**Supported Devices:**
- **YubiKey** (5 Series, Security Key)
- **Google Titan** Security Keys
- **Feitian** Security Keys
- **SoloKeys**
- Platform authenticators (Windows Hello, Touch ID, Face ID)

---

## Server Configuration

MFA is configured via environment variables in your Docker deployment.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MFA_ENABLED` | `false` | Enable MFA feature globally |
| `MFA_REQUIRED` | `false` | Require MFA for all users (not yet enforced) |
| `MFA_ISSUER` | `SafeShare` | Issuer name shown in authenticator apps |
| `MFA_TOTP_ENABLED` | `true` | Enable TOTP as an MFA method |
| `MFA_WEBAUTHN_ENABLED` | `true` | Enable WebAuthn as an MFA method |
| `MFA_RECOVERY_CODES_COUNT` | `10` | Number of recovery codes to generate (5-20) |
| `MFA_CHALLENGE_EXPIRY_MINUTES` | `5` | How long MFA challenges remain valid (1-30) |

### Example Docker Configuration

```bash
docker run -d -p 8080:8080 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=SafeShare2025! \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e MFA_ENABLED=true \
  -e MFA_ISSUER="My Company SafeShare" \
  -e MFA_TOTP_ENABLED=true \
  -e MFA_WEBAUTHN_ENABLED=true \
  -e MFA_RECOVERY_CODES_COUNT=10 \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  --name safeshare \
  safeshare:latest
```

### WebAuthn Requirements

WebAuthn requires HTTPS for production use. In development, `localhost` is permitted.

```bash
# Production WebAuthn requires PUBLIC_URL with https
-e PUBLIC_URL=https://share.example.com
```

---

## User Setup Guide

### Setting up TOTP

1. **Navigate to Security Settings**
   - Log in to your SafeShare dashboard
   - Go to the "Security" section
   - Click "Enable MFA"

2. **Scan QR Code**
   - Open your authenticator app
   - Tap "Add Account" or the + button
   - Scan the QR code displayed on screen
   - Alternatively, manually enter the secret key

3. **Verify Setup**
   - Enter the 6-digit code from your authenticator app
   - Click "Verify"
   - The code must match the current time window

4. **Save Recovery Codes**
   - **IMPORTANT:** Save your recovery codes in a secure location
   - Each code can only be used once
   - These codes are your only way to access your account if you lose your authenticator

### Setting up WebAuthn

1. **Navigate to Security Settings**
   - Log in to your SafeShare dashboard
   - Go to the "Security" section
   - Under "Hardware Keys", click "Register New Key"

2. **Insert/Activate Your Security Key**
   - Insert your hardware key (USB) or prepare your platform authenticator
   - Your browser will prompt you to activate the key
   - Touch the key when it blinks or use biometric authentication

3. **Name Your Key**
   - Give your key a descriptive name (e.g., "YubiKey 5 - Office")
   - This helps identify which key is which if you have multiple

4. **Verify Registration**
   - The key will appear in your credentials list
   - You can register multiple keys for redundancy

### Recovery Codes

Recovery codes are single-use backup codes for accessing your account when your primary MFA method is unavailable.

**Format:** `XXXX-XXXX-XXXX-XXXX` (16 hexadecimal characters)

**Best Practices:**
- Store codes in a password manager
- Print and store in a secure physical location
- Do not store codes digitally alongside your password
- Each code can only be used once
- Regenerate codes if you suspect they've been compromised

**Regenerating Recovery Codes:**
1. Go to Security settings
2. Click "Regenerate Recovery Codes"
3. This invalidates all previous codes
4. Save the new codes immediately

---

## Login with MFA

When MFA is enabled, the login process has two steps:

### Step 1: Password Authentication
1. Enter your username and password
2. Click "Sign In"
3. If MFA is enabled, you'll see the MFA verification screen

### Step 2: MFA Verification

**Using TOTP:**
1. Open your authenticator app
2. Enter the current 6-digit code
3. Click "Verify"

**Using WebAuthn:**
1. Click "Use Security Key" (if both methods are available)
2. Insert/activate your hardware key
3. Touch the key when prompted

**Using Recovery Code:**
1. Click "Use Recovery Code"
2. Enter one of your unused recovery codes
3. Click "Verify"
4. Note: This code is now permanently used

### Challenge Expiry

MFA challenges expire after the configured time (default: 5 minutes). If expired:
- You'll receive an error message
- Start the login process again from the beginning

---

## Managing MFA

### Disabling TOTP

1. Go to Security settings
2. Click "Disable TOTP"
3. Enter a current valid TOTP code to confirm
4. TOTP will be disabled and recovery codes deleted

### Removing WebAuthn Credentials

1. Go to Security settings
2. Find the credential in the Hardware Keys list
3. Click the delete icon
4. Confirm deletion

### Renaming WebAuthn Credentials

1. Go to Security settings
2. Find the credential in the Hardware Keys list
3. Click the edit/rename icon
4. Enter a new name
5. Save changes

---

## Admin MFA Management

Administrators can view and reset MFA for users who have lost access to their authenticators.

### Viewing User MFA Status

**Via Admin Dashboard:**
1. Go to Admin Dashboard > Users
2. Click on a user to view details
3. MFA status shows TOTP enabled, WebAuthn credentials, and recovery codes remaining

**Via API:**
```bash
curl -X GET "https://share.example.com/admin/api/users/{user_id}/mfa/status" \
  -H "Cookie: admin_session=..."
```

### Resetting User MFA

**Important Security Notes:**
- Admin cannot reset MFA for other admin users (security protection)
- Admin users must disable their own MFA
- All MFA reset actions are logged for audit purposes

**Via Admin Dashboard:**
1. Go to Admin Dashboard > Users
2. Find the user who needs MFA reset
3. Click "Reset MFA"
4. Confirm the action

**Via API:**
```bash
curl -X POST "https://share.example.com/admin/api/users/{user_id}/mfa/reset" \
  -H "Cookie: admin_session=..." \
  -H "X-CSRF-Token: ..."
```

**What Gets Reset:**
- TOTP secret is deleted
- All WebAuthn credentials are deleted
- All recovery codes are deleted
- User can set up MFA again from scratch

---

## API Reference

### User MFA Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/user/mfa/status` | Get current MFA status |
| `POST` | `/api/user/mfa/totp/setup` | Start TOTP setup, get QR code |
| `POST` | `/api/user/mfa/totp/verify` | Verify TOTP setup with code |
| `DELETE` | `/api/user/mfa/totp` | Disable TOTP (requires valid code) |
| `POST` | `/api/user/mfa/recovery-codes/regenerate` | Generate new recovery codes |

### WebAuthn Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/user/webauthn/credentials` | List registered credentials |
| `POST` | `/api/user/webauthn/register/begin` | Start credential registration |
| `POST` | `/api/user/webauthn/register/finish` | Complete registration |
| `POST` | `/api/user/webauthn/authenticate/begin` | Start authentication |
| `POST` | `/api/user/webauthn/authenticate/finish` | Complete authentication |
| `DELETE` | `/api/user/webauthn/credentials/{id}` | Delete a credential |
| `PATCH` | `/api/user/webauthn/credentials/{id}` | Rename a credential |

### Login MFA Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Returns `mfa_required: true` if MFA enabled |
| `POST` | `/api/auth/login/verify-mfa` | Complete login with MFA code |

### Admin MFA Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/api/users/{id}/mfa/status` | Get user's MFA status |
| `POST` | `/admin/api/users/{id}/mfa/reset` | Reset user's MFA |

---

## Security Considerations

### TOTP Security

- **Secret Storage:** TOTP secrets are encrypted using AES-256-GCM when `ENCRYPTION_KEY` is configured
- **Timing Protection:** All TOTP validation takes a minimum of 100ms to prevent timing attacks
- **Code Window:** Codes are valid for 30 seconds with standard tolerance

### WebAuthn Security

- **Phishing Resistance:** WebAuthn binds credentials to the origin (domain)
- **Clone Detection:** Sign count validation detects cloned authenticators
- **Transport Security:** WebAuthn requires HTTPS (except localhost)

### Recovery Codes

- **Storage:** Recovery codes are stored as bcrypt hashes
- **Single Use:** Each code can only be used once
- **Generation:** Codes use 128 bits of cryptographic randomness

### Challenge Security

- **Expiry:** MFA challenges expire after the configured time (default: 5 minutes)
- **IP Binding:** Challenges are bound to the IP address that initiated login
- **Rate Limiting:** Maximum 5 attempts per challenge
- **DoS Protection:** Maximum 10,000 total challenges and 10 per IP address

### Audit Logging

All MFA-related actions are logged:
- TOTP setup/verification/disable
- WebAuthn registration/authentication/deletion
- Recovery code usage
- Admin MFA resets (logged at WARNING level)

---

## Troubleshooting

### "Invalid TOTP code"

**Possible Causes:**
1. **Time sync issue:** Ensure your phone's time is synchronized
   - Enable automatic time sync in device settings
   - Check that timezone is correct

2. **Wrong account:** Verify you're using the correct authenticator entry

3. **Code expired:** TOTP codes change every 30 seconds - enter the new code

### "Registration session expired"

The WebAuthn registration ceremony timed out. This happens if:
- You took too long to activate your security key
- The browser tab was backgrounded
- Network issues delayed the response

**Solution:** Click "Register" again to start a new session.

### "No WebAuthn credentials registered"

You're trying to authenticate with WebAuthn but haven't registered any keys.

**Solution:** Register a security key first from the Security settings.

### "SECURITY: Potential cloned authenticator detected"

This warning appears in logs when the WebAuthn sign count is lower than expected, which could indicate:
- A cloned authenticator
- A key that was backed up and restored

**Action:** Investigate immediately - this could be a security incident.

### User Locked Out

If a user loses access to their authenticator and recovery codes:

1. **Admin Reset:** An administrator can reset their MFA
2. **User Re-enrollment:** After reset, user sets up MFA again
3. **Prevention:** Encourage users to:
   - Register multiple WebAuthn keys
   - Store recovery codes securely
   - Enable authenticator app backup (if available)

### WebAuthn Not Working

**Browser Support:**
- Chrome 67+
- Firefox 60+
- Safari 13+
- Edge 79+

**Requirements:**
- HTTPS required (except localhost)
- User interaction required (can't be automated)
- Pop-up blockers may interfere

**Platform Authenticator Issues:**
- Ensure biometric hardware is working
- Check that Windows Hello / Touch ID is configured
- Some VMs don't support platform authenticators

---

## Additional Resources

- [WebAuthn Developer Guide](https://webauthn.guide/)
- [TOTP RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
- [FIDO Alliance](https://fidoalliance.org/)
- [SafeShare Security Documentation](./SECURITY.md)
