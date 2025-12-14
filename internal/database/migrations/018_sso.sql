-- Migration 018: SSO/OIDC Integration support
--
-- Creates tables for Single Sign-On (SSO) with OIDC providers:
-- - sso_providers: SSO provider configurations (Google, Okta, Azure AD, etc.)
-- - user_sso_links: Links local users to SSO provider identities
-- - sso_states: Temporary OAuth2 state tokens for CSRF protection
--
-- Date: 2025-12-10
-- Version: v1.4.0

-- ============================================================================
-- SSO PROVIDERS TABLE
-- ============================================================================
-- Stores SSO provider configurations. Each provider represents an external
-- identity provider (IdP) like Google, Okta, Azure AD, etc.
-- The client_secret is encrypted with the system encryption key.
CREATE TABLE IF NOT EXISTS sso_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,                  -- Display name (e.g., "Google", "Okta")
    slug TEXT NOT NULL UNIQUE,                  -- URL-friendly identifier (e.g., "google", "okta")
    type TEXT NOT NULL DEFAULT 'oidc',          -- Provider type: 'oidc' or 'saml'
    enabled INTEGER NOT NULL DEFAULT 0,         -- Whether this provider is active
    
    -- OIDC/OAuth2 Configuration
    client_id TEXT,                             -- OAuth2 client ID
    client_secret TEXT,                         -- OAuth2 client secret (encrypted)
    issuer_url TEXT,                            -- OIDC issuer URL for discovery
    
    -- Optional custom endpoints (override discovery)
    authorization_url TEXT,                     -- Custom authorization endpoint
    token_url TEXT,                             -- Custom token endpoint
    userinfo_url TEXT,                          -- Custom userinfo endpoint
    jwks_url TEXT,                              -- Custom JWKS endpoint
    
    -- OAuth2 Configuration
    scopes TEXT DEFAULT 'openid profile email', -- Space-separated OAuth2 scopes
    redirect_url TEXT,                          -- Callback URL (auto-generated if empty)
    
    -- User provisioning settings
    auto_provision INTEGER NOT NULL DEFAULT 0,  -- Create users on first SSO login
    default_role TEXT DEFAULT 'user',           -- Role for auto-provisioned users
    domain_allowlist TEXT,                      -- Comma-separated email domains allowed (empty = all)
    
    -- Display settings
    icon_url TEXT,                              -- Provider icon URL for login page
    button_color TEXT,                          -- Button background color (hex)
    button_text_color TEXT,                     -- Button text color (hex)
    display_order INTEGER DEFAULT 0,            -- Sort order on login page
    
    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sso_providers_slug ON sso_providers(slug);
CREATE INDEX IF NOT EXISTS idx_sso_providers_enabled ON sso_providers(enabled);
CREATE INDEX IF NOT EXISTS idx_sso_providers_type ON sso_providers(type);

-- ============================================================================
-- USER SSO LINKS TABLE
-- ============================================================================
-- Links local users to their SSO provider identities.
-- A user can be linked to multiple SSO providers.
-- The external_id is the unique identifier from the SSO provider (sub claim).
CREATE TABLE IF NOT EXISTS user_sso_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider_id INTEGER NOT NULL,
    external_id TEXT NOT NULL,                  -- Subject claim from provider (unique per provider)
    external_email TEXT,                        -- Email from provider (for matching/display)
    external_name TEXT,                         -- Display name from provider
    
    -- Token storage (for token refresh if needed)
    access_token TEXT,                          -- Encrypted access token (optional)
    refresh_token TEXT,                         -- Encrypted refresh token (optional)
    token_expires_at DATETIME,                  -- When access token expires
    
    -- Metadata
    last_login_at DATETIME,                     -- Last successful SSO login
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE,
    UNIQUE (provider_id, external_id)           -- Each external ID can only link to one user per provider
);

CREATE INDEX IF NOT EXISTS idx_user_sso_links_user_id ON user_sso_links(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sso_links_provider_id ON user_sso_links(provider_id);
CREATE INDEX IF NOT EXISTS idx_user_sso_links_external_id ON user_sso_links(provider_id, external_id);
CREATE INDEX IF NOT EXISTS idx_user_sso_links_external_email ON user_sso_links(external_email);

-- ============================================================================
-- SSO STATES TABLE
-- ============================================================================
-- Stores temporary OAuth2 state tokens for CSRF protection during login flow.
-- States expire after a short time (typically 10 minutes).
-- Includes nonce for OIDC ID token validation.
CREATE TABLE IF NOT EXISTS sso_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state TEXT NOT NULL UNIQUE,                 -- Random state value for CSRF protection
    nonce TEXT NOT NULL,                        -- Random nonce for ID token validation
    provider_id INTEGER NOT NULL,
    return_url TEXT,                            -- URL to redirect to after login
    user_id INTEGER,                            -- If linking existing account
    created_ip TEXT,                            -- IP that initiated the flow
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_sso_states_state ON sso_states(state);
CREATE INDEX IF NOT EXISTS idx_sso_states_expires_at ON sso_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_sso_states_provider_id ON sso_states(provider_id);
