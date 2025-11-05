# SafeShare Documentation

This directory contains comprehensive documentation for SafeShare.

## Documentation Files

### [CLAUDE.md](CLAUDE.md)
**Developer Guide** - For developers working on SafeShare codebase

**Contents:**
- Architecture overview and request flow
- Admin dashboard architecture (routes, security, components)
- Build commands and development workflows
- Configuration reference with all environment variables
- Database schema and migrations
- Security features implementation details
- Frontend architecture (embedded files)
- Common development tasks
- Troubleshooting guide

**Audience:** Developers, DevOps engineers, AI assistants (Claude Code)

---

### [SECURITY.md](SECURITY.md)
**Security Features** - Enterprise security implementation guide

**Contents:**
- Encryption at rest (AES-256-GCM)
- File extension blacklist
- Password protection for files
- Enhanced audit logging with JSON examples
- Admin dashboard security (sessions, CSRF, rate limiting)
- IP blocking functionality
- Production security features (7 critical features)
- Security best practices
- Compliance mapping (HIPAA, SOC 2, GDPR, PCI-DSS)
- Security audit checklist

**Audience:** Security teams, compliance officers, system administrators

---

### [FRONTEND.md](FRONTEND.md)
**Frontend Guide** - Web UI customization and features

**Contents:**
- Public web UI features (upload interface, QR codes, dark mode)
- Admin dashboard UI (login, files, IP blocking, settings)
- Technical stack (HTML, CSS, JavaScript)
- File structure and organization
- API integration details
- Browser compatibility
- Customization guide (colors, branding, text)
- Performance considerations

**Audience:** Frontend developers, UI/UX designers

---

### [REVERSE_PROXY.md](REVERSE_PROXY.md)
**Reverse Proxy Configuration** - Production deployment examples

**Contents:**
- Traefik configuration (Docker Compose)
- Nginx configuration
- Caddy configuration
- Apache configuration
- SSL/TLS setup
- Header configuration for proper IP detection
- Load balancing examples

**Audience:** DevOps engineers, system administrators

---

## Quick Links

### Getting Started
- Main README: [../README.md](../README.md)
- Quick Start: See main README for Docker commands

### Common Tasks
- **Enable Admin Dashboard**: Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` ([SECURITY.md](SECURITY.md#admin-dashboard-security))
- **Setup Encryption**: Generate key and set `ENCRYPTION_KEY` ([SECURITY.md](SECURITY.md#encryption-at-rest))
- **Configure Reverse Proxy**: See [REVERSE_PROXY.md](REVERSE_PROXY.md)
- **Customize Frontend**: See [FRONTEND.md](FRONTEND.md#customization)
- **Development Setup**: See [CLAUDE.md](CLAUDE.md#build-and-development-commands)

### Security
- **Admin Security**: [SECURITY.md](SECURITY.md#admin-dashboard-security)
- **Password Protection**: [SECURITY.md](SECURITY.md#password-protection)
- **Audit Logging**: [SECURITY.md](SECURITY.md#enhanced-audit-logging)
- **Best Practices**: [SECURITY.md](SECURITY.md#security-best-practices)

---

## Documentation Standards

All documentation follows these standards:
- ✅ **Markdown format** for GitHub compatibility
- ✅ **Code examples** with syntax highlighting
- ✅ **Step-by-step instructions** for complex tasks
- ✅ **Configuration examples** with explanations
- ✅ **Security warnings** where applicable
- ✅ **Cross-references** between documents

## Contributing

When updating documentation:
1. Keep examples up-to-date with code changes
2. Test all commands and configurations
3. Update cross-references when moving content
4. Add security warnings for sensitive operations
5. Include version information for external dependencies

## Support

For issues and questions:
- GitHub Issues: Report bugs and request features
- Documentation Issues: Open PR with corrections

---

**Last Updated:** November 2025
**SafeShare Version:** 1.0
