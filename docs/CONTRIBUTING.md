# Contributing to SafeShare

Thank you for your interest in contributing to SafeShare! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Security](#security)
- [Community](#community)

---

## Code of Conduct

### Our Pledge

We are committed to providing a friendly, safe, and welcoming environment for all contributors, regardless of experience level, gender identity, sexual orientation, disability, personal appearance, body size, race, ethnicity, age, religion, or nationality.

### Expected Behavior

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Trolling or insulting/derogatory comments
- Personal or political attacks
- Publishing others' private information
- Other conduct inappropriate in a professional setting

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the project maintainers. All complaints will be reviewed and investigated promptly and fairly.

---

## Getting Started

### Prerequisites

- Go 1.21 or later
- Docker (for testing)
- Git
- Basic understanding of Go and web development

### Quick Start

1. **Fork the repository** on GitHub

2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/safeshare.git
   cd safeshare
   ```

3. **Add upstream remote:**
   ```bash
   git remote add upstream https://github.com/fjmerc/safeshare.git
   ```

4. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## Development Setup

### Local Development (with Docker for tests)

SafeShare requires Docker for running tests since there's no local Go installation requirement.

```bash
# Build and run locally
docker build -t safeshare:dev .
docker run -p 8080:8080 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=devpassword \
  safeshare:dev

# Run tests
docker run --rm -v "$PWD":/app -w /app golang:1.24 go test ./internal/... -v
```

### IDE Setup

**VS Code (Recommended):**
1. Install the Go extension
2. Open the workspace
3. Go extension will prompt to install tools - accept all

**GoLand:**
1. Open the project
2. Configure Go SDK (1.21+)
3. Enable Go modules

### Environment Variables for Development

```bash
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=devpassword
export ENCRYPTION_KEY=$(openssl rand -hex 32)
export LOG_LEVEL=debug
```

---

## How to Contribute

### Types of Contributions

1. **Bug Fixes** - Fix issues reported in GitHub Issues
2. **Features** - Implement new functionality
3. **Documentation** - Improve or add documentation
4. **Tests** - Add test coverage
5. **Performance** - Optimize existing code
6. **Security** - Fix vulnerabilities (see [Security](#security))

### Finding Issues to Work On

- Look for issues labeled `good first issue` for beginners
- Issues labeled `help wanted` are actively seeking contributors
- Check the project roadmap for planned features

### Before You Start

1. **Check existing issues** - Someone may already be working on it
2. **Open an issue first** for significant changes
3. **Discuss your approach** - Get feedback before investing time
4. **Follow Git Flow** - See [VERSION_STRATEGY.md](VERSION_STRATEGY.md)

---

## Pull Request Process

### 1. Branch Naming

Follow these conventions:
- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `docs/description` - Documentation changes
- `perf/description` - Performance improvements
- `refactor/description` - Code refactoring

### 2. Development Workflow

```bash
# 1. Sync with upstream
git fetch upstream
git checkout develop
git merge upstream/develop

# 2. Create feature branch
git checkout -b feature/your-feature

# 3. Make changes
# ... edit files ...

# 4. Run tests
docker run --rm -v "$PWD":/app -w /app golang:1.24 go test ./internal/... -cover

# 5. Commit changes
git add .
git commit -m "feat: add your feature description"

# 6. Push to your fork
git push origin feature/your-feature

# 7. Create Pull Request on GitHub
```

### 3. Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `style` - Formatting (no code change)
- `refactor` - Code restructuring
- `perf` - Performance improvement
- `test` - Adding tests
- `chore` - Maintenance tasks

**Examples:**
```
feat(upload): add chunked upload support for large files

fix(auth): prevent session fixation on login

docs(api): add webhook endpoint documentation

perf(download): implement streaming for large files
```

### 4. Pull Request Template

When creating a PR, include:

```markdown
## Summary
Brief description of changes

## Changes
- Change 1
- Change 2

## Testing
How was this tested?

## Related Issues
Fixes #123

## Checklist
- [ ] Tests pass (`docker run --rm -v "$PWD":/app -w /app golang:1.24 go test ./internal/...`)
- [ ] Coverage >= 60%
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if user-facing change)
- [ ] No security vulnerabilities introduced
```

### 5. Review Process

1. **Automated checks** must pass (tests, coverage, linting)
2. **Code review** by maintainer
3. **Address feedback** - make requested changes
4. **Approval** from maintainer
5. **Merge** by maintainer

### 6. After Merge

- Delete your feature branch
- Sync your fork with upstream
- Celebrate your contribution!

---

## Coding Standards

### Go Style Guide

Follow the official [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) and [Effective Go](https://golang.org/doc/effective_go).

**Key Points:**
- Use `gofmt` for formatting
- Use meaningful variable names
- Keep functions focused and small
- Handle errors explicitly
- Add comments for exported functions

### Project-Specific Guidelines

1. **Error Handling:**
   ```go
   // Good
   if err != nil {
       slog.Error("failed to process", "error", err, "file_id", id)
       return fmt.Errorf("process file %d: %w", id, err)
   }

   // Avoid
   if err != nil {
       return err  // No context
   }
   ```

2. **Logging:**
   ```go
   // Use structured logging with slog
   slog.Info("file uploaded",
       "claim_code", code,
       "size", size,
       "user_id", userID,
   )
   ```

3. **Security:**
   - Always validate user input
   - Use parameterized SQL queries
   - Sanitize filenames
   - Check authorization

4. **Configuration:**
   ```go
   // Use environment variables via config package
   cfg := config.Load()
   maxSize := cfg.MaxFileSize
   ```

### Frontend Standards

- Vanilla JavaScript (no frameworks)
- CSS in separate files
- Mobile-responsive design
- Dark mode support
- Accessibility (ARIA labels, keyboard navigation)

---

## Testing Requirements

### Coverage Requirements

- **Minimum coverage:** 60% for `internal/*` packages
- **Excluded:** `cmd/*` packages (CLI entry points)

### Running Tests

```bash
# Full test suite
docker run --rm -v "$PWD":/app -w /app golang:1.24 go test ./internal/... -cover

# With coverage report
docker run --rm -v "$PWD":/app -w /app golang:1.24 sh -c \
  "go test ./internal/... -coverprofile=coverage.out && go tool cover -func=coverage.out | grep total"

# Specific package
docker run --rm -v "$PWD":/app -w /app golang:1.24 go test -v ./internal/handlers/...

# With race detection
docker run --rm -v "$PWD":/app -w /app golang:1.24 go test -race ./internal/...
```

### Writing Tests

1. **Unit tests** for functions and methods
2. **Integration tests** for API endpoints
3. **Table-driven tests** for multiple scenarios

**Example:**
```go
func TestUploadHandler(t *testing.T) {
    tests := []struct {
        name       string
        file       string
        wantStatus int
    }{
        {"valid file", "test.txt", http.StatusCreated},
        {"blocked extension", "test.exe", http.StatusBadRequest},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### Security Testing

Before submitting PRs that touch security-sensitive code:

1. Run the bug-hunter agent for security audit
2. Check for OWASP Top 10 vulnerabilities
3. Verify input validation
4. Test authentication/authorization

---

## Documentation

### When to Update Documentation

- Adding new features → Update relevant docs
- Changing API → Update API_REFERENCE.md
- Configuration changes → Update README.md and relevant docs
- User-facing changes → Update CHANGELOG.md

### Documentation Files

| File | Purpose |
|------|---------|
| README.md | Project overview and quick start |
| CHANGELOG.md | Version history |
| docs/API_REFERENCE.md | API documentation |
| docs/ARCHITECTURE.md | Technical architecture |
| docs/SECURITY.md | Security features |
| docs/PRODUCTION.md | Production deployment |

### Documentation Style

- Use clear, concise language
- Include code examples
- Add screenshots for UI features
- Keep examples up-to-date
- Test all commands before documenting

---

## Security

### Reporting Security Issues

**Do NOT open public issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md#security-reporting) for responsible disclosure process.

### Security Checklist for PRs

- [ ] No hardcoded credentials or secrets
- [ ] Input validation for user data
- [ ] SQL queries are parameterized
- [ ] File paths are validated
- [ ] Authentication checked where needed
- [ ] Authorization enforced
- [ ] Sensitive data not logged
- [ ] Rate limiting considered

---

## Community

### Getting Help

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and community discussion
- **Documentation** - Check docs before asking

### Recognition

Contributors are recognized in:
- CHANGELOG.md for significant contributions
- GitHub contributor graph
- Release notes for major features

### Maintainers

The project is maintained by the core team. Maintainers:
- Review and merge PRs
- Manage releases
- Make architectural decisions
- Enforce code of conduct

---

## License

By contributing to SafeShare, you agree that your contributions will be licensed under the MIT License.

### Developer Certificate of Origin

By making a contribution to this project, I certify that:

1. The contribution was created in whole or in part by me and I have the right to submit it under the open source license indicated in the file; or

2. The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open source license and I have the right under that license to submit that work with modifications; or

3. The contribution was provided directly to me by some other person who certified (1) or (2) and I have not modified it.

---

## Thank You!

Your contributions make SafeShare better for everyone. We appreciate your time and effort!

---

**Last Updated:** December 2025
**SafeShare Version:** 1.5.0
