# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Guidelines

### Sequential Thinking - REQUIRED FOR ALL TASKS

**CRITICAL**: Always use sequential thinking (via `mcp__sequential-thinking__sequentialthinking` tool) when analyzing problems, making decisions, or executing multi-step tasks.

**When to use sequential thinking:**
- Analyzing code or architecture
- Planning changes or implementations
- Debugging issues
- Making decisions about approach
- Understanding user requirements
- Evaluating tradeoffs
- ANY complex task that requires reasoning

**Why this matters:**
- Provides transparent reasoning process
- Catches errors before execution
- Allows for mid-course corrections
- Documents decision-making for the user

**Usage:**
- Use sequential thinking at the START of each task
- Break down the problem into steps
- Verify assumptions before acting
- Adjust approach if initial thinking reveals issues

### File Operations - REQUIRED TOOL USAGE

**CRITICAL**: Always use the filesystem MCP tools for file operations instead of the built-in Read/Write/Edit tools.

**Required MCP Tools:**
- `mcp__filesystem__read_text_file` - Read text files (replaces Read tool)
- `mcp__filesystem__write_file` - Write/create files (replaces Write tool)
- `mcp__filesystem__edit_file` - Edit existing files (replaces Edit tool)
- `mcp__filesystem__read_multiple_files` - Read multiple files efficiently
- `mcp__filesystem__list_directory` - List directory contents
- `mcp__filesystem__search_files` - Search for files by pattern

**When NOT to use MCP filesystem tools:**
- Use Glob for file pattern matching (e.g., `**/*.go`)
- Use Grep for content search within files
- Use Bash for git operations, Docker commands, and system commands

### Specialized Agents - USE FOR COMPLEX TASKS

**Code & Development:**
- **golang-pro** - Go idioms, concurrency, performance optimization
- **code-reviewer** - Pre-PR reviews, security audits, OWASP vulnerabilities
- **refactoring-specialist** - Technical debt cleanup, complexity reduction

**Debugging & Analysis:**
- **debugger** - Performance issues, timeouts, encryption bugs
- **integration-consultant** - Cross-domain problems (CDN + encryption + streaming)

**Database:**
- **database-optimizer** - SQLite query optimization, indexing strategies
- **sql-pro** - Complex queries, performance tuning

**Infrastructure:**
- **platform-engineer** - Docker optimization, deployment automation
- **network-engineer** - Reverse proxy (Traefik), Cloudflare CDN

**Security & Quality:**
- **bug-hunter** - Security audits, vulnerability detection, correctness analysis (REQUIRED before testing)

**Testing:**
- **app-testing** - Web UI testing, API testing, integration tests

**Planning:**
- **Plan** - Implementation planning, architecture design
- **Explore** - Codebase exploration, finding files/patterns

### Security Audit & Testing Procedures - REQUIRED FOR ALL CODE CHANGES

**CRITICAL**: This project has no local Go installation. All tests MUST run in Docker using the golang:1.24 image.

**Development Workflow Order:**

1. **Write/modify code** - Implement the feature or fix
2. **SECURITY AUDIT FIRST** - Run bug-hunter agent BEFORE testing
3. **Fix security issues** - Address any vulnerabilities found
4. **Run tests** - Delegate to app-testing agent
5. **Fix test failures** - Address any failing tests
6. **Verify coverage** - Ensure coverage meets 60% threshold

**Bug Hunter Agent - REQUIRED BEFORE TESTING:**

**When to invoke bug-hunter:**
- After writing new code (features, bug fixes, refactors)
- BEFORE running the test suite
- When modifying security-critical code (auth, encryption, webhooks)
- After making database schema changes
- When handling user input or external data

**Why audit before testing:**
- Catches security vulnerabilities early (SQL injection, XSS, etc.)
- Identifies logic bugs before they become test failures
- Prevents shipping insecure code that passes tests
- Reduces rework by finding issues before test suite runs

**How to invoke:**
```
Use Task tool with subagent_type: bug-hunter
Provide context about what code changed and what to audit
```

**What bug-hunter checks:**
- SQL injection vulnerabilities
- XSS and injection attacks
- Authentication/authorization bypasses
- Input validation issues
- Race conditions and concurrency bugs
- Resource leaks (memory, file handles, goroutines)
- Logic errors and off-by-one bugs
- OWASP Top 10 vulnerabilities

**Test Execution Rules:**

1. **NEVER run tests directly** - Do NOT use `go test` on the host
2. **Run bug-hunter FIRST** - Security audit before app-testing agent
3. **THEN delegate to app-testing agent** - Use Task tool with `subagent_type: app-testing`
4. **Agent runs tests, YOU fix code** - Agent only executes tests; you fix failures
5. **All tests use Docker** - Every test command must use: `docker run --rm -v "$PWD":/app -w /app golang:1.24 go test ...`

**Required Docker Test Format:**
```bash
# Full test suite with coverage (internal packages only)
docker run --rm -v "$PWD":/app -w /app golang:1.24 sh -c \
  "go test ./internal/... -cover -coverprofile=coverage.out -covermode=atomic && \
   go tool cover -func=coverage.out | grep total"

# Specific package tests
docker run --rm -v "$PWD":/app -w /app golang:1.24 go test -v ./internal/handlers/...
```

**Coverage Requirements:**
- Minimum coverage threshold: **60%** (for `internal/*` packages only)
- **Coverage scope**: Only `internal/*` packages are measured
- **Excluded**: `cmd/*` packages (CLI tools and main() functions)
- **Rationale**: CLI entry points and main() functions are difficult to unit test and are better tested via integration/E2E tests. This follows Go community best practices.

**Test-Driven Development Workflow:**
1. Make code changes
2. Delegate test execution to app-testing agent with Docker commands
3. Agent reports results (pass/fail, coverage, specific failures)
4. If tests fail: YOU analyze the failure and fix the code
5. Repeat until all tests pass
6. Verify coverage meets 60% threshold

### Git Flow Workflow - REQUIRED FOR ALL CHANGES

**CRITICAL**: This project follows Git Flow branching strategy (see `docs/VERSION_STRATEGY.md`).

**NEVER commit directly to `develop` or `main` branches.**

**Before making ANY code changes:**

1. **Create a feature/bugfix/docs branch FIRST**:
   ```bash
   ./scripts/new-branch.sh
   # Or manually: git checkout -b feature/your-feature-name
   ```

2. **Make your changes** on the feature branch

3. **STOP - Get user approval before committing**:
   - **CRITICAL**: DO NOT automatically commit, push, or create PRs
   - Show the user a summary of changes
   - For frontend changes: Remind user that Docker rebuild is required
   - Ask if user wants to test changes first
   - **WAIT for explicit user confirmation**

4. **Update CHANGELOG.md**: Add entry to `[Unreleased]` section (ONLY after user approval)

5. **Commit changes** (ONLY after user approval):
   ```bash
   git add .
   git commit -m "type: description"
   ```
   **Important**: Do NOT add attribution lines like "🤖 Generated with [Claude Code]"

6. **Push branch** (ONLY after user approval):
   ```bash
   git push -u origin feature/your-feature-name
   ```

7. **Create Pull Request** (ONLY after user approval):
   ```bash
   gh pr create --base develop --fill
   ```

8. **User reviews and merges PR**:
   ```bash
   ./scripts/merge-pr.sh
   ```

**Branch naming conventions:**
- `feature/*` - New features (base: develop)
- `bugfix/*` - Bug fixes (base: develop)
- `perf/*` - Performance improvements (base: develop)
- `docs/*` - Documentation updates (base: develop)
- `hotfix/*` - Emergency production fixes (base: main)
- `release/*` - Release preparation (base: develop)

### Creating Releases - REQUIRED STEPS

**CRITICAL**: Complete ALL steps. Missing the GitHub Release is a common mistake.

1. Create release branch from develop
2. Update version files (CHANGELOG.md, version.go)
3. Commit version bump
4. Merge to main
5. Create annotated git tag
6. Push main and tag
7. **CREATE GITHUB RELEASE** (DO NOT SKIP):
   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" --notes "..."
   ```
8. Merge back to develop
9. Delete release branch

**Remember**: Git tags and GitHub Releases are different. Always create BOTH.

### Cloudflare CDN Cache Purge - CRITICAL FOR UI CHANGES

**CRITICAL**: SafeShare is deployed behind Cloudflare CDN (share.mercitlabs.com). After ANY frontend deployment, you MUST purge the Cloudflare cache.

**Why this matters:**
- Users will see STALE versions even after Docker container is updated
- Browser hard refresh does NOT clear CDN cache

**When to purge cache:**
- After merging PRs that modify frontend files (internal/static/web/)
- After creating releases with UI changes
- When users report not seeing recent changes

**How to purge cache (Manual):**
1. Log into Cloudflare Dashboard (mercitlabs.com account)
2. Navigate to: **mercitlabs.com** → **Caching** → **Configuration**
3. Click **"Purge Cache"** → **"Custom Purge"**
4. Enter URLs: `https://share.mercitlabs.com/assets/*.js`, etc.

**Verification:**
```bash
curl -sI https://share.mercitlabs.com/assets/app.js | grep cf-cache-status
# Expected after purge: cf-cache-status: MISS
```

### Before Making Changes

**IMPORTANT**: Always reference `docs/VERSION_STRATEGY.md` for semantic versioning, branching strategy, and CHANGELOG.md guidelines.

### Updating CHANGELOG.md

**CRITICAL**: `docs/CHANGELOG.md` is ONLY for user-facing application changes.

**What belongs in CHANGELOG.md:**
- ✅ New features users can use
- ✅ Bug fixes that affect users
- ✅ Breaking changes to application behavior
- ✅ Security improvements users should know about

**What does NOT belong:**
- ❌ Development scripts (new-branch.sh, merge-pr.sh, etc.)
- ❌ CLAUDE.md updates or workflow documentation
- ❌ Git Flow process changes
- ❌ Developer tooling or CI/CD changes

## Build and Development Commands

### Docker Rebuild Policy

**CRITICAL**: When making changes to Go code, **DO NOT** automatically rebuild. Instead:

1. **Inform the user** that a rebuild is required
2. **Show the rebuild command** they should run
3. **Wait for user confirmation** before proceeding

**Rebuild command:**
```bash
docker build -t safeshare:latest . && docker stop safeshare && docker rm safeshare && \
docker run -d --name safeshare -p 8080:8080 -e ADMIN_USERNAME=admin -e ADMIN_PASSWORD=admin123 \
-v safeshare-data:/app/data -v safeshare-uploads:/app/uploads safeshare:latest
```

**Exception:** Only rebuild automatically if user explicitly asks.

### Local Development
```bash
go build -o safeshare ./cmd/safeshare
./safeshare
```

### Docker Development
```bash
# Build Docker image
docker build -t safeshare:latest .

# Run with enterprise security features
docker run -d -p 8080:8080 \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD=SafeShare2025! \
  -e ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e BLOCKED_EXTENSIONS=".exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar" \
  -v safeshare-data:/app/data \
  -v safeshare-uploads:/app/uploads \
  --name safeshare \
  safeshare:latest

# View logs
docker logs -f safeshare
```

### Testing Endpoints

For comprehensive API testing examples, see **docs/API_REFERENCE_FOR_TESTING.md**.

**Quick examples:**
```bash
# Upload file
curl -X POST -F "file=@test.txt" -F "expires_in_hours=24" http://localhost:8080/api/upload

# Download file
curl -O http://localhost:8080/api/claim/<CLAIM_CODE>

# Health check
curl http://localhost:8080/health
```

### Import Tool (CLI Admin Utility)

SafeShare includes a command-line import tool for bulk file imports without network upload.

**Build:**
```bash
go build -o cmd/import-file/import-file ./cmd/import-file
```

**Usage:**
```bash
./cmd/import-file/import-file \
  --source /path/to/file.iso \
  --filename "Ubuntu 22.04.iso" \
  --expires 168 \
  --db /app/data/safeshare.db \
  --uploads /app/uploads
```

**Full documentation:** See `cmd/import-file/README.md`

### Encryption Migration Tool (CLI Admin Utility)

Migration tool for converting legacy encrypted files to SFSE1 format.

**Why migrate?**
- Eliminates format confusion vulnerability (P1 finding)
- Streaming encryption/decryption for large files
- Better HTTP Range support

**Build:**
```bash
go build -o cmd/migrate-encryption/migrate-encryption ./cmd/migrate-encryption
```

**Usage:**
```bash
# Dry run
./cmd/migrate-encryption/migrate-encryption \
  --db /path/to/safeshare.db \
  --uploads /path/to/uploads \
  --enckey "your-64-char-hex-key" \
  --dry-run

# Actual migration
./cmd/migrate-encryption/migrate-encryption \
  --db /path/to/safeshare.db \
  --uploads /path/to/uploads \
  --enckey "your-64-char-hex-key"
```

**Full documentation:** See `cmd/migrate-encryption/README.md`

## Architecture Reference

For detailed implementation documentation, see **docs/ARCHITECTURE.md**:
- User Authentication Architecture
- Admin Dashboard Architecture
- Core Architecture Overview
- Configuration
- Settings Persistence
- Frontend Architecture
- Chunked Upload Architecture

## Common Development Tasks

### Adding New API Endpoints

1. Create handler function in `internal/handlers/`
2. Register route in `cmd/safeshare/main.go`
3. If modifying frontend, update `internal/static/web/` files
4. Rebuild Docker image to embed frontend changes

See **docs/ARCHITECTURE.md** for detailed handler patterns.

### Modifying Database Schema

1. Update schema in `internal/database/db.go`
2. Update model structs in `internal/models/`
3. Update query functions in `internal/database/files.go`
4. Consider migration strategy (SQLite limitations)

See **docs/ARCHITECTURE.md** for database schema details.

### Frontend Changes

**Important**: Frontend is embedded at compile time.

1. Edit files in `internal/static/web/`
2. Rebuild Go binary or Docker image
3. Restart application
4. **Remember to purge Cloudflare CDN cache** (see above)

### Security Considerations

When adding features:
- **Always** validate user input (see `internal/utils/validation.go`)
- Use parameterized SQL queries (no string concatenation)
- Log security events with client IP and user agent
- Check file extensions against blacklist
- Return appropriate HTTP status codes

See **docs/SECURITY.md** for comprehensive security guidelines.

### Reverse Proxy Configuration

SafeShare is designed to run behind reverse proxies:
- Set `PUBLIC_URL` environment variable
- **Security**: SafeShare validates proxy headers using `TRUST_PROXY_HEADERS` (default: "auto")
- This prevents IP spoofing when exposed to internet

See **docs/REVERSE_PROXY.md** for detailed proxy configurations.

## Troubleshooting

### Encryption Issues
- Key must be exactly 64 hexadecimal characters (32 bytes for AES-256)
- Generate key: `openssl rand -hex 32`
- Lost key = lost files (no recovery possible)
- Check logs for "failed to decrypt file" errors

### Container Issues
- Check logs: `docker logs safeshare`
- Verify health: `docker inspect safeshare | jq '.[0].State.Health'`
- Common issues: port conflicts, volume permissions, invalid env vars

### Frontend Not Updating
- Frontend is embedded at compile time
- Must rebuild Docker image after frontend changes
- Clear browser cache if seeing old UI
- **Remember to purge Cloudflare CDN cache**

## Additional Documentation

- **docs/VERSION_STRATEGY.md** - Semantic versioning, branching strategy, changelog guidelines
- **docs/ARCHITECTURE.md** - Detailed technical architecture documentation
- **docs/CHUNKED_UPLOAD.md** - Chunked upload API specifications and usage
- **docs/API_REFERENCE_FOR_TESTING.md** - Comprehensive API testing examples
- **docs/HTTP_RANGE_SUPPORT.md** - HTTP Range request implementation
- **docs/REVERSE_PROXY.md** - Reverse proxy configurations (Traefik, nginx, etc.)
- **docs/SECURITY.md** - Security features and best practices
- **cmd/import-file/README.md** - Import tool documentation
- **cmd/migrate-encryption/README.md** - Migration tool documentation
