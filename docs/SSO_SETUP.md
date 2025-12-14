# Single Sign-On (SSO) Setup Guide

SafeShare supports Single Sign-On (SSO) via OpenID Connect (OIDC), enabling users to authenticate with enterprise identity providers. This guide covers SSO configuration, provider setup, and management for both administrators and users.

## Table of Contents

- [Overview](#overview)
- [Supported Providers](#supported-providers)
- [Server Configuration](#server-configuration)
- [Admin Setup Guide](#admin-setup-guide)
  - [Creating an SSO Provider](#creating-an-sso-provider)
  - [Provider Configuration Fields](#provider-configuration-fields)
  - [Testing Provider Connectivity](#testing-provider-connectivity)
- [Provider Configuration Examples](#provider-configuration-examples)
  - [Okta](#okta)
  - [Azure Active Directory](#azure-active-directory)
  - [Google Workspace](#google-workspace)
  - [Auth0](#auth0)
  - [Keycloak](#keycloak)
- [User Experience](#user-experience)
  - [SSO Login Flow](#sso-login-flow)
  - [Account Linking](#account-linking)
  - [Account Unlinking](#account-unlinking)
- [API Reference](#api-reference)
  - [Public Endpoints](#public-endpoints)
  - [Authenticated User Endpoints](#authenticated-user-endpoints)
  - [Admin Endpoints](#admin-endpoints)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Overview

Single Sign-On (SSO) allows users to authenticate with SafeShare using their existing enterprise identity provider (IdP) credentials. When SSO is enabled, users see provider-branded login buttons on the login page and can authenticate without creating a separate SafeShare password.

**Key Features:**
- OpenID Connect (OIDC) protocol support
- Automatic user provisioning (JIT provisioning)
- Account linking for existing users
- Email domain allowlists for security
- Customizable login button appearance
- Multiple provider support
- Token refresh capabilities
- RP-Initiated Logout support

---

## Supported Providers

SafeShare supports any OIDC-compliant identity provider. Tested providers include:

| Provider | Type | Notes |
|----------|------|-------|
| **Okta** | OIDC | Full support, recommended |
| **Azure Active Directory** | OIDC | Full support, including B2C |
| **Google Workspace** | OIDC | Full support |
| **Auth0** | OIDC | Full support |
| **Keycloak** | OIDC | Full support, self-hosted |
| **OneLogin** | OIDC | Full support |
| **Ping Identity** | OIDC | Full support |
| **AWS Cognito** | OIDC | Full support |

**Requirements:**
- Provider must support OpenID Connect 1.0
- Provider must expose OIDC Discovery endpoint (`/.well-known/openid-configuration`)
- HTTPS required for production (HTTP allowed only for localhost development)

---

## Server Configuration

SSO is configured via environment variables in your Docker deployment.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_SSO` | `false` | Enable SSO feature globally |
| `SSO_AUTO_PROVISION` | `false` | Create users automatically on first SSO login |
| `SSO_DEFAULT_ROLE` | `user` | Default role for auto-provisioned users (`user` or `admin`) |
| `SSO_SESSION_LIFETIME` | `480` | SSO session lifetime in minutes (default: 8 hours) |
| `SSO_STATE_EXPIRY_MINUTES` | `10` | OAuth2 state token expiry (5-60 minutes) |

### Example Docker Configuration

```bash
docker run -d -p 8080:8080 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=SafeShare2025! \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e PUBLIC_URL=https://share.example.com \
  -e ENABLE_SSO=true \
  -e SSO_AUTO_PROVISION=true \
  -e SSO_DEFAULT_ROLE=user \
  -e SSO_SESSION_LIFETIME=480 \
  -e SSO_STATE_EXPIRY_MINUTES=10 \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  --name safeshare \
  safeshare:latest
```

### Configuration Validation

SafeShare validates SSO configuration on startup:
- `SSO_DEFAULT_ROLE` must be `user` or `admin`
- `SSO_SESSION_LIFETIME` must be between 5 and 43200 minutes (30 days)
- `SSO_STATE_EXPIRY_MINUTES` must be between 5 and 60 minutes

---

## Admin Setup Guide

### Creating an SSO Provider

SSO providers are configured through the Admin API. You must have admin authentication to create providers.

**Via API (Recommended):**

```bash
# First, authenticate as admin
ADMIN_SESSION=$(curl -s -c - -X POST "https://share.example.com/admin/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SafeShare2025!"}' | grep admin_session | awk '{print $7}')

# Get CSRF token
CSRF_TOKEN=$(curl -s -c - -b "admin_session=$ADMIN_SESSION" \
  "https://share.example.com/admin/dashboard" | grep -oP 'csrf_token=\K[^"]+' || \
  curl -s -b "admin_session=$ADMIN_SESSION" "https://share.example.com/admin/api/csrf-token" | jq -r '.token')

# Create SSO provider
curl -X POST "https://share.example.com/admin/api/sso/providers" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b "admin_session=$ADMIN_SESSION" \
  -d '{
    "name": "Okta",
    "slug": "okta",
    "type": "oidc",
    "enabled": true,
    "issuer_url": "https://your-domain.okta.com",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "redirect_url": "https://share.example.com/api/auth/sso/okta/callback",
    "scopes": "openid profile email",
    "auto_provision": true,
    "default_role": "user",
    "domain_allowlist": "example.com,subsidiary.com",
    "button_color": "#007dc1",
    "button_text_color": "#ffffff"
  }'
```

### Provider Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Display name shown on login button |
| `slug` | Yes | URL-safe identifier (lowercase, hyphens allowed, 1-64 chars) |
| `type` | No | Provider type: `oidc` (default) or `saml` (future) |
| `enabled` | No | Whether provider is active (default: `false`) |
| `issuer_url` | Yes | OIDC Issuer URL (must support discovery) |
| `client_id` | Yes | OAuth2 Client ID from your IdP |
| `client_secret` | No | OAuth2 Client Secret (required for most flows) |
| `redirect_url` | No | OAuth2 callback URL (auto-generated if not set) |
| `authorization_url` | No | Override discovery authorization endpoint |
| `token_url` | No | Override discovery token endpoint |
| `userinfo_url` | No | Override discovery userinfo endpoint |
| `jwks_url` | No | Override discovery JWKS endpoint |
| `scopes` | No | Space-separated scopes (default: `openid profile email`) |
| `auto_provision` | No | Create users on first login (default: `false`) |
| `default_role` | No | Role for new users: `user` or `admin` (default: `user`) |
| `domain_allowlist` | No | Comma-separated allowed email domains |
| `icon_url` | No | URL to provider icon (displayed on button) |
| `button_color` | No | Hex color for login button background |
| `button_text_color` | No | Hex color for login button text |
| `display_order` | No | Sort order on login page (lower = first) |

### Testing Provider Connectivity

Before enabling a provider for users, test the OIDC discovery connection:

```bash
curl -X POST "https://share.example.com/admin/api/sso/providers/{provider_id}/test" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b "admin_session=$ADMIN_SESSION"
```

**Successful Response:**
```json
{
  "success": true,
  "provider_id": 1,
  "provider_name": "Okta",
  "issuer_url": "https://your-domain.okta.com",
  "test_duration": "245.123ms",
  "message": "OIDC discovery successful"
}
```

**Failed Response:**
```json
{
  "success": false,
  "provider_id": 1,
  "provider_name": "Okta",
  "issuer_url": "https://your-domain.okta.com",
  "test_duration": "1.234s",
  "error": "failed to perform OIDC discovery: context deadline exceeded"
}
```

---

## Provider Configuration Examples

### Okta

**1. Create Application in Okta:**
- Go to Applications > Create App Integration
- Select "OIDC - OpenID Connect"
- Select "Web Application"
- Configure:
  - Sign-in redirect URI: `https://share.example.com/api/auth/sso/okta/callback`
  - Sign-out redirect URI: `https://share.example.com/login`
  - Assignments: Assign users/groups who should access SafeShare

**2. Create SafeShare Provider:**
```bash
curl -X POST "https://share.example.com/admin/api/sso/providers" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b "admin_session=$ADMIN_SESSION" \
  -d '{
    "name": "Okta",
    "slug": "okta",
    "enabled": true,
    "issuer_url": "https://your-domain.okta.com",
    "client_id": "0oaxxxxxxxxxxxxxxxxx",
    "client_secret": "your-client-secret-from-okta",
    "redirect_url": "https://share.example.com/api/auth/sso/okta/callback",
    "scopes": "openid profile email",
    "auto_provision": true,
    "domain_allowlist": "example.com",
    "button_color": "#007dc1",
    "button_text_color": "#ffffff"
  }'
```

### Azure Active Directory

**1. Register Application in Azure AD:**
- Go to Azure Portal > Azure Active Directory > App registrations
- Click "New registration"
- Configure:
  - Name: SafeShare SSO
  - Supported account types: Choose based on your needs
  - Redirect URI: Web - `https://share.example.com/api/auth/sso/azure/callback`
- Note the Application (client) ID and Directory (tenant) ID
- Go to Certificates & secrets > New client secret

**2. Create SafeShare Provider:**
```bash
curl -X POST "https://share.example.com/admin/api/sso/providers" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b "admin_session=$ADMIN_SESSION" \
  -d '{
    "name": "Microsoft",
    "slug": "azure",
    "enabled": true,
    "issuer_url": "https://login.microsoftonline.com/{tenant-id}/v2.0",
    "client_id": "your-application-client-id",
    "client_secret": "your-client-secret",
    "redirect_url": "https://share.example.com/api/auth/sso/azure/callback",
    "scopes": "openid profile email",
    "auto_provision": true,
    "domain_allowlist": "example.com,example.onmicrosoft.com",
    "button_color": "#0078d4",
    "button_text_color": "#ffffff"
  }'
```

**Note:** Replace `{tenant-id}` with your Azure AD tenant ID, or use `common` for multi-tenant apps.

### Google Workspace

**1. Create OAuth 2.0 Credentials in Google Cloud Console:**
- Go to APIs & Services > Credentials
- Click "Create Credentials" > "OAuth client ID"
- Application type: Web application
- Authorized redirect URIs: `https://share.example.com/api/auth/sso/google/callback`

**2. Create SafeShare Provider:**
```bash
curl -X POST "https://share.example.com/admin/api/sso/providers" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b "admin_session=$ADMIN_SESSION" \
  -d '{
    "name": "Google",
    "slug": "google",
    "enabled": true,
    "issuer_url": "https://accounts.google.com",
    "client_id": "your-client-id.apps.googleusercontent.com",
    "client_secret": "your-client-secret",
    "redirect_url": "https://share.example.com/api/auth/sso/google/callback",
    "scopes": "openid profile email",
    "auto_provision": true,
    "domain_allowlist": "example.com",
    "button_color": "#4285f4",
    "button_text_color": "#ffffff"
  }'
```

### Auth0

**1. Create Application in Auth0:**
- Go to Applications > Create Application
- Select "Regular Web Applications"
- Configure:
  - Allowed Callback URLs: `https://share.example.com/api/auth/sso/auth0/callback`
  - Allowed Logout URLs: `https://share.example.com/login`

**2. Create SafeShare Provider:**
```bash
curl -X POST "https://share.example.com/admin/api/sso/providers" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b "admin_session=$ADMIN_SESSION" \
  -d '{
    "name": "Auth0",
    "slug": "auth0",
    "enabled": true,
    "issuer_url": "https://your-tenant.auth0.com/",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "redirect_url": "https://share.example.com/api/auth/sso/auth0/callback",
    "scopes": "openid profile email",
    "auto_provision": true,
    "button_color": "#eb5424",
    "button_text_color": "#ffffff"
  }'
```

### Keycloak

**1. Create Client in Keycloak:**
- Go to your realm > Clients > Create
- Configure:
  - Client ID: safeshare
  - Client Protocol: openid-connect
  - Access Type: confidential
  - Valid Redirect URIs: `https://share.example.com/api/auth/sso/keycloak/callback`

**2. Create SafeShare Provider:**
```bash
curl -X POST "https://share.example.com/admin/api/sso/providers" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b "admin_session=$ADMIN_SESSION" \
  -d '{
    "name": "Keycloak",
    "slug": "keycloak",
    "enabled": true,
    "issuer_url": "https://keycloak.example.com/realms/your-realm",
    "client_id": "safeshare",
    "client_secret": "your-client-secret",
    "redirect_url": "https://share.example.com/api/auth/sso/keycloak/callback",
    "scopes": "openid profile email",
    "auto_provision": true,
    "button_color": "#4d4d4d",
    "button_text_color": "#ffffff"
  }'
```

---

## User Experience

### SSO Login Flow

1. **User visits login page** - Sees traditional login form plus SSO provider buttons
2. **User clicks SSO button** - Redirected to identity provider
3. **User authenticates with IdP** - Using corporate credentials
4. **IdP redirects back** - With authorization code
5. **SafeShare processes callback** - Validates tokens, creates/links user
6. **User logged in** - Redirected to dashboard (or original destination)

**Login Page with SSO:**
```
+----------------------------------+
|         User Login               |
|                                  |
|  Username: [____________]        |
|  Password: [____________]        |
|                                  |
|  [        Sign In        ]       |
|                                  |
|  ─────── or sign in with ─────── |
|                                  |
|  [🔑 Sign in with Okta    ]      |
|  [🔑 Sign in with Google  ]      |
+----------------------------------+
```

### Account Linking

Existing users can link their SafeShare account to an SSO provider to enable SSO login while keeping their existing account.

**To link an account:**

```bash
# As authenticated user, initiate linking
curl -X POST "https://share.example.com/api/auth/sso/link" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $USER_CSRF_TOKEN" \
  -b "user_session=$USER_SESSION" \
  -d '{
    "provider_slug": "okta",
    "return_url": "/dashboard"
  }'
```

**Response:**
```json
{
  "authorization_url": "https://your-domain.okta.com/oauth2/v1/authorize?..."
}
```

The user is then redirected to the IdP to authenticate, and upon return, their accounts are linked.

**View linked providers:**

```bash
curl -X GET "https://share.example.com/api/auth/sso/linked" \
  -b "user_session=$USER_SESSION"
```

**Response:**
```json
{
  "linked_providers": [
    {
      "provider_slug": "okta",
      "provider_name": "Okta",
      "external_email": "user@example.com",
      "external_name": "John Doe",
      "linked_at": "2024-01-15T10:30:00Z",
      "last_login_at": "2024-01-20T14:22:00Z"
    }
  ]
}
```

### Account Unlinking

Users can unlink their SSO provider if they want to stop using SSO login:

```bash
curl -X DELETE "https://share.example.com/api/auth/sso/link/okta" \
  -H "X-CSRF-Token: $USER_CSRF_TOKEN" \
  -b "user_session=$USER_SESSION"
```

**Response:**
```json
{
  "message": "SSO link removed successfully"
}
```

**Note:** After unlinking, the user must use password-based login (ensure they have a password set first).

---

## API Reference

### Public Endpoints

These endpoints are accessible without authentication.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/sso/providers` | List enabled SSO providers (public info only) |
| `GET` | `/api/auth/sso/{provider}/login` | Initiate SSO login flow |
| `GET` | `/api/auth/sso/{provider}/callback` | OAuth2 callback handler |

**Example - List Providers:**
```bash
curl "https://share.example.com/api/auth/sso/providers"
```

**Response:**
```json
{
  "providers": [
    {
      "name": "Okta",
      "slug": "okta",
      "icon_url": "https://example.com/okta-icon.png",
      "button_color": "#007dc1",
      "button_text_color": "#ffffff"
    }
  ],
  "enabled": true
}
```

### Authenticated User Endpoints

These endpoints require user authentication.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/sso/linked` | List user's linked SSO providers |
| `POST` | `/api/auth/sso/link` | Initiate account linking |
| `DELETE` | `/api/auth/sso/link/{provider}` | Unlink SSO provider |
| `POST` | `/api/auth/sso/refresh` | Refresh SSO OAuth2 tokens |
| `POST` | `/api/auth/sso/logout` | SSO logout (local + optional IdP) |

**SSO Logout with IdP Redirect:**
```bash
curl -X POST "https://share.example.com/api/auth/sso/logout" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $USER_CSRF_TOKEN" \
  -b "user_session=$USER_SESSION" \
  -d '{
    "idp_logout": true,
    "post_logout_url": "/login"
  }'
```

**Response:**
```json
{
  "message": "Logged out successfully",
  "idp_logout_url": "https://your-domain.okta.com/logout?client_id=...&post_logout_redirect_uri=..."
}
```

### Admin Endpoints

These endpoints require admin authentication and CSRF token.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/api/sso/providers` | List all providers with stats |
| `POST` | `/admin/api/sso/providers` | Create new provider |
| `GET` | `/admin/api/sso/providers/{id}` | Get provider details |
| `PUT` | `/admin/api/sso/providers/{id}` | Update provider |
| `DELETE` | `/admin/api/sso/providers/{id}` | Delete provider |
| `POST` | `/admin/api/sso/providers/{id}/test` | Test provider connectivity |
| `GET` | `/admin/api/sso/links` | List all SSO links (paginated) |
| `DELETE` | `/admin/api/sso/links/{id}` | Delete SSO link (admin unlink) |

**List Providers with Stats:**
```bash
curl "https://share.example.com/admin/api/sso/providers" \
  -b "admin_session=$ADMIN_SESSION"
```

**Response:**
```json
{
  "providers": [
    {
      "id": 1,
      "name": "Okta",
      "slug": "okta",
      "type": "oidc",
      "enabled": true,
      "issuer_url": "https://your-domain.okta.com",
      "client_id": "0oaxxxxxxxxxxxxxxxxx",
      "scopes": "openid profile email",
      "auto_provision": true,
      "default_role": "user",
      "domain_allowlist": "example.com",
      "linked_users_count": 42,
      "login_count_24h": 15,
      "created_at": "2024-01-10T09:00:00Z",
      "updated_at": "2024-01-15T11:30:00Z"
    }
  ],
  "total_count": 1
}
```

**List SSO Links (Paginated):**
```bash
curl "https://share.example.com/admin/api/sso/links?page=1&per_page=50&provider_id=1" \
  -b "admin_session=$ADMIN_SESSION"
```

**Response:**
```json
{
  "links": [
    {
      "id": 1,
      "user_id": 5,
      "username": "jdoe",
      "email": "jdoe@example.com",
      "provider_id": 1,
      "provider_slug": "okta",
      "provider_name": "Okta",
      "external_id": "00uxxxxxxxxxxxxxxxxx",
      "external_email": "john.doe@example.com",
      "external_name": "John Doe",
      "last_login_at": "2024-01-20T14:22:00Z",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "page": 1,
  "per_page": 50,
  "total_count": 42,
  "total_pages": 1
}
```

---

## Security Considerations

### State and Nonce Validation

SafeShare implements OAuth2 best practices for CSRF protection:

- **State Parameter:** Cryptographically random, stored server-side, validated on callback
- **Nonce Parameter:** Embedded in ID token, validated to prevent replay attacks
- **State Expiry:** Configurable (default: 10 minutes), states auto-expire
- **One-Time Use:** States are deleted immediately after validation

### Email Domain Allowlists

For enterprise security, restrict SSO logins to specific email domains:

```json
{
  "domain_allowlist": "example.com,subsidiary.example.com"
}
```

When configured:
- Only users with email addresses matching allowed domains can authenticate
- Attempts from other domains are rejected with "domain_not_allowed" error
- Leave empty to allow all domains

### Email Verification

SafeShare considers email verification status from the IdP:

- **Verified emails:** Can be linked to existing accounts with matching email
- **Unverified emails:** Only create new accounts (no automatic linking)

This prevents account takeover when an IdP doesn't verify email addresses.

### HTTPS Requirements

Production SSO requires HTTPS:

- **Issuer URL:** Must use HTTPS (except localhost)
- **Redirect URL:** Must use HTTPS (except localhost)
- **Cookies:** Set with `Secure` flag when `HTTPS_ENABLED=true`

For development with localhost, HTTP is permitted.

### Token Storage

OAuth2 tokens from SSO providers are stored securely:

- Access tokens and refresh tokens stored in database
- Tokens are associated with user SSO links
- Can be refreshed using the `/api/auth/sso/refresh` endpoint

### Client Secret Protection

- Client secrets are never exposed in API responses
- Stored in database, not in configuration files
- Use environment variable injection for initial setup if needed

### Audit Logging

All SSO-related actions are logged:

- Login initiations and completions
- Account linking/unlinking
- Token refreshes
- Admin provider management
- Failed authentication attempts

Logs include client IP addresses for security analysis.

---

## Troubleshooting

### "SSO is not enabled"

**Cause:** The `ENABLE_SSO` environment variable is not set to `true`.

**Solution:**
```bash
docker run ... -e ENABLE_SSO=true ...
```

### "Provider not found" or "Provider is disabled"

**Causes:**
1. Provider slug is incorrect
2. Provider has not been created
3. Provider exists but `enabled` is `false`

**Solutions:**
- Verify provider slug matches exactly (case-sensitive, lowercase)
- Create the provider via Admin API
- Enable the provider: `PUT /admin/api/sso/providers/{id}` with `{"enabled": true}`

### "Failed to perform OIDC discovery"

**Causes:**
1. Issuer URL is incorrect
2. IdP is unreachable from SafeShare server
3. DNS resolution failure
4. TLS/SSL certificate issues

**Solutions:**
- Verify issuer URL ends without trailing slash (usually)
- Test connectivity: `curl https://your-idp.com/.well-known/openid-configuration`
- Check firewall rules allow outbound HTTPS to IdP
- Verify IdP SSL certificate is valid

### "Invalid state" or "State has expired"

**Causes:**
1. User took too long to complete IdP authentication (>10 minutes by default)
2. User bookmarked or reused the callback URL
3. Multiple browser tabs with SSO login
4. State was already consumed (one-time use)

**Solution:** Start the login process again from the beginning.

### "Nonce mismatch"

**Cause:** The nonce in the ID token doesn't match the expected value. This could indicate:
- A replay attack attempt
- Token manipulation
- IdP configuration issue

**Solution:**
- If persistent, check IdP configuration
- Ensure IdP includes nonce in ID tokens
- Contact IdP administrator if issue persists

### "Email domain not allowed"

**Cause:** User's email domain is not in the provider's `domain_allowlist`.

**Solution:**
- Add the domain to the allowlist
- Or remove the allowlist to allow all domains:
  ```bash
  curl -X PUT "https://share.example.com/admin/api/sso/providers/{id}" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    -b "admin_session=$ADMIN_SESSION" \
    -d '{"domain_allowlist": ""}'
  ```

### "SSO auto-provisioning is disabled and no linked account exists"

**Cause:** User tried to log in via SSO but:
1. Their SSO identity is not linked to an existing account
2. Auto-provisioning is disabled for this provider

**Solutions:**
- Enable auto-provisioning for the provider
- Or have the user create an account first, then link their SSO identity

### User Linked Wrong Account

If a user accidentally linked SSO to the wrong SafeShare account:

**Admin Solution:**
```bash
# Find the link
curl "https://share.example.com/admin/api/sso/links?provider_id={provider_id}" \
  -b "admin_session=$ADMIN_SESSION"

# Delete the link
curl -X DELETE "https://share.example.com/admin/api/sso/links/{link_id}" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -b "admin_session=$ADMIN_SESSION"
```

The user can then log into the correct account and re-link.

### SSO Button Not Appearing

**Causes:**
1. SSO not globally enabled (`ENABLE_SSO=false`)
2. No providers configured
3. All providers are disabled
4. JavaScript error on login page

**Solutions:**
- Set `ENABLE_SSO=true`
- Create and enable at least one provider
- Check browser console for JavaScript errors

---

## Additional Resources

- [OpenID Connect Core Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [SafeShare Security Documentation](./SECURITY.md)
- [SafeShare MFA Setup Guide](./MFA_SETUP.md)
