# SafeShare Testing Guide

This document provides comprehensive information about the SafeShare test suite.

## Table of Contents

- [Overview](#overview)
- [Running Tests](#running-tests)
- [Test Organization](#test-organization)
- [Test Coverage](#test-coverage)
- [Writing Tests](#writing-tests)
- [Continuous Integration](#continuous-integration)

## Overview

SafeShare has a comprehensive test suite with **24 test files** covering:

- **Unit tests** for handlers, utils, middleware
- **Integration tests** for end-to-end workflows
- **Edge case tests** for boundary conditions and attack vectors
- **Benchmarks** for performance-critical code
- **Load/stress tests** for concurrent operations

### Test Statistics

- **~6000+ lines of test code**
- **200+ test cases**
- **Target coverage: 85%+**
- **Security testing**: SQL injection, XSS, path traversal, etc.

## Running Tests

### Quick Start

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific package
go test ./internal/handlers/

# Run specific test
go test ./internal/handlers/ -run TestUploadHandler_ValidUpload
```

### Recommended Test Scripts

#### Run Tests with Coverage

```bash
# Use the provided script
./scripts/run-tests.sh

# Or manually
go test ./... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out
```

**Output:**
- Terminal: Coverage summary by package
- `coverage.html`: Detailed line-by-line coverage visualization

#### Run Tests with Race Detection

```bash
# Use the provided script
./scripts/run-tests-race.sh

# Or manually
go test ./... -race
```

**Important:** Always run race detection before deploying to production.

#### Run Load/Stress Tests

```bash
# Load tests are skipped by default (use -short flag to skip them)
go test ./internal/benchmarks/ -run TestLoad

# Run specific load test
go test ./internal/benchmarks/ -run TestLoad_1000ConcurrentUploads -timeout=15m
```

**Note:** Load tests can take several minutes and create many database entries.

#### Run Benchmarks

```bash
# Run all benchmarks
go test ./... -bench=. -benchmem

# Run specific benchmark
go test ./internal/benchmarks/ -bench=BenchmarkUploadSmallFile
```

## Test Organization

### Directory Structure

```
internal/
├── handlers/          # HTTP handler unit tests
│   ├── upload_test.go         (774 lines)
│   ├── claim_test.go          (611 lines)
│   ├── upload_chunked_test.go (914 lines)
│   ├── claim_range_test.go    (NEW - HTTP Range support)
│   ├── admin_test.go
│   └── user_auth_test.go
│
├── utils/             # Utility function tests
│   ├── validation_test.go     (610 lines - security tests)
│   ├── encryption_test.go
│   ├── password_test.go
│   ├── sanitize_test.go
│   └── range_test.go
│
├── middleware/        # Middleware tests
│   ├── ratelimit_test.go      (617 lines)
│   ├── security_test.go
│   └── ipblock_test.go
│
├── database/          # Database layer tests
│   ├── settings_test.go       (NEW - settings persistence)
│   └── ...
│
├── integration/       # End-to-end tests
│   ├── integration_test.go    (506 lines)
│   ├── database_test.go       (concurrency tests)
│   ├── cleanup_test.go
│   ├── cleanup_chunked_test.go (NEW)
│   └── chunked_upload_test.go
│
├── edgecases/         # Boundary and security tests
│   ├── boundary_test.go       (349 lines)
│   ├── error_recovery_test.go
│   └── malformed_input_test.go
│
└── benchmarks/        # Performance tests
    ├── upload_benchmark_test.go
    ├── database_benchmark_test.go
    ├── load_test.go
    └── load_stress_test.go     (NEW - 1000+ concurrent tests)
```

### Test Categories

#### 1. **Unit Tests**
- Test individual functions/handlers in isolation
- Mock dependencies using `testutil` package
- Fast execution (< 1 second per test)

**Example:**
```go
func TestUploadHandler_ValidUpload(t *testing.T) {
    db := testutil.SetupTestDB(t)
    cfg := testutil.SetupTestConfig(t)
    handler := UploadHandler(db, cfg)

    // Test upload logic
    // ...
}
```

#### 2. **Integration Tests**
- Test complete workflows across multiple components
- Use real database and filesystem
- Slower execution (1-5 seconds per test)

**Example:**
```go
func TestUploadDownloadWorkflow(t *testing.T) {
    // 1. Upload file
    // 2. Get claim code
    // 3. Download file
    // 4. Verify content matches
}
```

#### 3. **Edge Case Tests**
- Test boundary conditions (0 bytes, max size, etc.)
- Test invalid inputs
- Test attack vectors (SQL injection, path traversal, etc.)

**Example:**
```go
func TestUploadOneByteTooLarge(t *testing.T) {
    // Test file exactly 1 byte over max size
}
```

#### 4. **Load/Stress Tests**
- Test system under heavy load
- Skipped by default (use `-short=false`)
- Run before major releases

**Example:**
```go
func TestLoad_1000ConcurrentUploads(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }
    // Simulate 1000 concurrent uploads
}
```

## Test Coverage

### Coverage Goals

| Component | Target | Current (Est.) |
|-----------|--------|----------------|
| Handlers | 90%+ | ~90% |
| Utils | 95%+ | ~95% |
| Middleware | 85%+ | ~85% |
| Database | 75%+ | ~75% |
| Overall | 85%+ | ~85% |

### Viewing Coverage

```bash
# Generate coverage report
./scripts/run-tests.sh

# Open coverage.html in browser
open coverage.html  # macOS
xdg-open coverage.html  # Linux
```

### What's Tested

✅ **Core Functionality**
- File upload (simple and chunked)
- File download (full and range requests)
- User authentication and sessions
- Admin dashboard
- Rate limiting
- IP blocking

✅ **Security**
- SQL injection attempts
- Path traversal attacks
- Header injection
- Double extension attacks
- Homograph attacks
- XSS prevention
- CSRF protection

✅ **Edge Cases**
- Zero-byte files
- Files at exact size limits
- Extremely long filenames (255, 1000+ chars)
- Unicode filenames (Chinese, Russian, Arabic, emoji)
- Empty/nil inputs
- Concurrent operations

✅ **Performance**
- Upload benchmarks (small, medium, large files)
- Download benchmarks
- Rate limiter performance
- Database concurrency
- Cleanup worker efficiency

## Writing Tests

### Test Naming Conventions

```go
// Pattern: Test<FunctionName>_<Scenario>
func TestUploadHandler_ValidUpload(t *testing.T) {}
func TestUploadHandler_FileTooLarge(t *testing.T) {}
func TestUploadHandler_BlockedExtension(t *testing.T) {}

// Pattern: Benchmark<FunctionName>_<Variant>
func BenchmarkUploadSmallFile(b *testing.B) {}
func BenchmarkUploadMediumFile(b *testing.B) {}

// Pattern: TestLoad_<Scenario>
func TestLoad_1000ConcurrentUploads(t *testing.T) {}
```

### Using Table-Driven Tests

**Recommended for testing multiple inputs:**

```go
func TestFileValidation(t *testing.T) {
    tests := []struct {
        name     string
        filename string
        want     bool
    }{
        {"safe pdf", "document.pdf", true},
        {"blocked exe", "virus.exe", false},
        {"unicode", "文档.txt", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := IsFileAllowed(tt.filename)
            if got != tt.want {
                t.Errorf("got %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Test Helpers

Use the `testutil` package for common setup:

```go
// Setup test database (SQLite in-memory)
db := testutil.SetupTestDB(t)

// Setup test config with defaults
cfg := testutil.SetupTestConfig(t)

// Create multipart form for upload testing
body, contentType := testutil.CreateMultipartForm(t, fileContent, filename, options)

// Assert HTTP status code
testutil.AssertStatusCode(rr, http.StatusOK)
```

### Documentation for Complex Tests

Add doc comments for integration and complex tests:

```go
// TestUploadDownloadWorkflow tests the complete file upload and download lifecycle.
//
// This integration test verifies:
//  1. Client uploads a file with options (expiration: 24h, max_downloads: 3)
//  2. Server stores file and returns claim code with download URL
//  3. Client downloads file using claim code
//  4. Downloaded content matches uploaded content
//  5. Download count increments correctly in database
func TestUploadDownloadWorkflow(t *testing.T) {
    // ...
}
```

### Cleanup and Isolation

**Always use test isolation:**

```go
func TestSomething(t *testing.T) {
    // Each test gets its own DB and config
    db := testutil.SetupTestDB(t)  // In-memory SQLite
    cfg := testutil.SetupTestConfig(t)  // Temp directories

    // testutil automatically cleans up after test
    // No manual cleanup needed
}
```

## Continuous Integration

### Pre-Commit Checks

Before committing, run:

```bash
# 1. Run all tests
./scripts/run-tests.sh

# 2. Run race detector
./scripts/run-tests-race.sh

# 3. Check coverage threshold
go test ./... -cover | grep "coverage:"
```

### CI/CD Pipeline

Recommended GitHub Actions workflow:

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Run tests with coverage
        run: ./scripts/run-tests.sh

      - name: Run race detector
        run: ./scripts/run-tests-race.sh

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.out
```

## Troubleshooting

### Tests Failing on CI

**Issue:** Tests pass locally but fail on CI

**Solutions:**
- Check for race conditions: `go test -race ./...`
- Check for timing dependencies: Use `time.After` instead of `time.Sleep`
- Check for file path assumptions: Use `filepath.Join` for cross-platform paths

### Database Locked Errors

**Issue:** `database is locked` errors during concurrent tests

**Solutions:**
- Each test should use its own database via `testutil.SetupTestDB(t)`
- Don't share database connections between goroutines
- Enable WAL mode: `PRAGMA journal_mode=WAL`

### Load Tests Taking Too Long

**Issue:** Load tests timeout

**Solutions:**
- Load tests are skipped with `-short` flag by default
- Increase timeout: `go test -timeout=15m`
- Run load tests separately: `go test ./internal/benchmarks/ -run TestLoad`

## Best Practices

1. **Isolation**: Each test should be independent and not affect others
2. **Deterministic**: Tests should produce same result every time
3. **Fast**: Unit tests should run in < 1 second
4. **Readable**: Use descriptive test names and clear assertions
5. **Maintainable**: Use table-driven tests for multiple scenarios
6. **Security-focused**: Test attack vectors and edge cases
7. **Documented**: Add comments for complex test scenarios

## New Test Additions (This Branch)

### 1. Settings Persistence Tests (`internal/database/settings_test.go`)
- Tests database settings override environment variables
- Concurrent updates to different settings
- Settings persist across database restarts
- Idempotency of repeated updates

### 2. HTTP Range Request Tests (`internal/handlers/claim_range_test.go`)
- Single byte range requests (RFC 7233)
- Range from offset to end (`bytes=500-`)
- Suffix range requests (`bytes=-100`)
- Invalid range handling
- Resumable download simulation
- Download count increment for range requests

### 3. Chunked Upload Cleanup Tests (`internal/integration/cleanup_chunked_test.go`)
- Abandoned upload deletion (inactive > 24 hours)
- Active upload preservation
- Completed upload preservation
- Multiple abandoned uploads cleanup
- Configurable expiry times
- Missing chunk directory handling

### 4. Load/Stress Tests (`internal/benchmarks/load_stress_test.go`)
- 1000 concurrent uploads
- Quota enforcement under load
- Rate limiter under high load
- Cleanup worker with 10,000 expired files
- Concurrent downloads (1000 downloads)
- Database concurrency (1000 operations)
- Memory usage monitoring

## References

- [Go Testing Package](https://pkg.go.dev/testing)
- [Table-Driven Tests](https://github.com/golang/go/wiki/TableDrivenTests)
- [Go Test Coverage](https://go.dev/blog/cover)
- [SafeShare CLAUDE.md](../CLAUDE.md) - Development guidelines
- [SafeShare VERSION_STRATEGY.md](VERSION_STRATEGY.md) - Release process
