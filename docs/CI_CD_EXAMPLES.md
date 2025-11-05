# CI/CD Pipeline Examples - SafeShare

This guide provides complete CI/CD configurations for SafeShare across different platforms.

---

## Table of Contents

1. [GitHub Actions + GitHub Container Registry](#github-actions--github-container-registry)
2. [GitHub Actions + Docker Hub](#github-actions--docker-hub)
3. [GitLab CI/CD + GitLab Container Registry](#gitlab-cicd--gitlab-container-registry)
4. [Gitea + Drone CI](#gitea--drone-ci)
5. [Multi-Architecture Builds](#multi-architecture-builds)
6. [Automated Testing](#automated-testing)
7. [Security Scanning](#security-scanning)

---

## GitHub Actions + GitHub Container Registry

**Advantages**: Free, integrated, supports multi-arch builds, no external dependencies

### Setup

1. **Enable GitHub Container Registry**:
   - Go to Settings → Packages
   - Enable "Improved container support"

2. **Create Personal Access Token** (for pushing):
   - Settings → Developer settings → Personal access tokens
   - Scope: `write:packages`, `read:packages`
   - Or use automatic `GITHUB_TOKEN` (recommended)

### Workflow Configuration

`.github/workflows/build-and-push.yml`:

```yaml
name: Build and Push Docker Image

on:
  push:
    branches:
      - main
      - develop
    tags:
      - 'v*.*.*'
  pull_request:
    branches:
      - main

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
          cache: true

      - name: Run tests
        run: |
          go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...

      - name: Run go vet
        run: go vet ./...

      - name: Run staticcheck
        uses: dominikh/staticcheck-action@v1
        with:
          version: "2023.1.6"

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.txt

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=semver,pattern={{major}}
            type=sha,prefix={{branch}}-

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: ${{ github.event_name != 'pull_request' }}
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  create-release:
    needs: build-and-push
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/v')
    permissions:
      contents: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          generate_release_notes: true
          body: |
            ## Docker Images

            Pull the image:
            ```bash
            docker pull ghcr.io/${{ github.repository }}:${{ github.ref_name }}
            ```

            See [PRODUCTION.md](docs/PRODUCTION.md) for deployment instructions.
```

### Usage

```bash
# Pull image from GitHub Container Registry
docker pull ghcr.io/yourusername/safeshare:latest
docker pull ghcr.io/yourusername/safeshare:v1.0.0

# Authenticate (if private)
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Run
docker run -d -p 8080:8080 ghcr.io/yourusername/safeshare:latest
```

---

## GitHub Actions + Docker Hub

**Advantages**: Public registry, well-known, easy to use

### Setup

1. **Create Docker Hub account** (if needed)
2. **Create Access Token**:
   - Docker Hub → Account Settings → Security → New Access Token
3. **Add secrets to GitHub**:
   - Settings → Secrets → Actions
   - Add `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`

### Workflow Configuration

`.github/workflows/dockerhub.yml`:

```yaml
name: Build and Push to Docker Hub

on:
  push:
    branches:
      - main
    tags:
      - 'v*.*.*'

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ secrets.DOCKERHUB_USERNAME }}/safeshare
          tags: |
            type=raw,value=latest,enable={{is_default_branch}}
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
```

### Usage

```bash
# Pull from Docker Hub
docker pull yourusername/safeshare:latest
docker pull yourusername/safeshare:v1.0.0

# Run
docker run -d -p 8080:8080 yourusername/safeshare:latest
```

---

## GitLab CI/CD + GitLab Container Registry

**Advantages**: Integrated container registry, CI/CD included, can self-host

### Setup

1. **Enable Container Registry** (enabled by default on gitlab.com)
2. **Create GitLab Access Token** (optional, for local testing):
   - Settings → Access Tokens
   - Scope: `read_registry`, `write_registry`

### CI Configuration

`.gitlab-ci.yml`:

```yaml
stages:
  - test
  - build
  - release

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"
  IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
  LATEST_TAG: $CI_REGISTRY_IMAGE:latest

# Test stage
test:
  stage: test
  image: golang:1.21
  before_script:
    - go mod download
  script:
    - go test -v -race -coverprofile=coverage.txt ./...
    - go vet ./...
  coverage: '/coverage: \d+\.\d+% of statements/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.txt

# Build Docker image
build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $IMAGE_TAG .
    - docker push $IMAGE_TAG
    # Tag as latest if on main branch
    - |
      if [ "$CI_COMMIT_BRANCH" == "main" ]; then
        docker tag $IMAGE_TAG $LATEST_TAG
        docker push $LATEST_TAG
      fi
  only:
    - main
    - develop
    - tags

# Multi-arch build for tags
build-multiarch:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker buildx create --use
  script:
    - |
      docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --tag $CI_REGISTRY_IMAGE:$CI_COMMIT_TAG \
        --tag $LATEST_TAG \
        --push \
        .
  only:
    - tags

# Create GitLab release
release:
  stage: release
  image: registry.gitlab.com/gitlab-org/release-cli:latest
  script:
    - echo "Creating release for $CI_COMMIT_TAG"
  release:
    tag_name: '$CI_COMMIT_TAG'
    description: |
      ## Docker Image

      Pull the image:
      ```bash
      docker pull $CI_REGISTRY_IMAGE:$CI_COMMIT_TAG
      ```

      See [PRODUCTION.md](docs/PRODUCTION.md) for deployment instructions.
  only:
    - tags
```

### Usage

```bash
# Pull from GitLab Container Registry
docker pull registry.gitlab.com/yourusername/safeshare:latest
docker pull registry.gitlab.com/yourusername/safeshare:v1.0.0

# Authenticate (if private)
docker login registry.gitlab.com -u USERNAME -p ACCESS_TOKEN

# Run
docker run -d -p 8080:8080 registry.gitlab.com/yourusername/safeshare:latest
```

---

## Gitea + Drone CI

**Advantages**: Self-hosted, privacy-focused, lightweight

### Setup Gitea Container Registry

Gitea 1.17+ includes a built-in container registry.

**1. Enable in Gitea config** (`app.ini`):
```ini
[packages]
ENABLED = true

[storage.packages]
STORAGE_TYPE = local
PATH = data/packages
```

**2. Restart Gitea**:
```bash
docker restart gitea
```

**3. Create Personal Access Token**:
- Gitea → Settings → Applications → Generate New Token
- Scope: `write:package`

### Setup Drone CI

**1. Install Drone Server**:

`docker-compose.yml`:
```yaml
version: '3'

services:
  drone-server:
    image: drone/drone:2
    container_name: drone-server
    ports:
      - "3000:80"
    volumes:
      - drone-data:/data
    environment:
      - DRONE_GITEA_SERVER=https://gitea.yourdomain.com
      - DRONE_GITEA_CLIENT_ID=your-oauth-client-id
      - DRONE_GITEA_CLIENT_SECRET=your-oauth-client-secret
      - DRONE_RPC_SECRET=your-rpc-secret
      - DRONE_SERVER_HOST=drone.yourdomain.com
      - DRONE_SERVER_PROTO=https
      - DRONE_USER_CREATE=username:yourusername,admin:true
    restart: always

  drone-runner:
    image: drone/drone-runner-docker:1
    container_name: drone-runner
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DRONE_RPC_PROTO=http
      - DRONE_RPC_HOST=drone-server
      - DRONE_RPC_SECRET=your-rpc-secret
      - DRONE_RUNNER_CAPACITY=2
      - DRONE_RUNNER_NAME=docker-runner
    restart: always
    depends_on:
      - drone-server

volumes:
  drone-data:
```

**2. Create OAuth Application in Gitea**:
- Gitea → Settings → Applications → Manage OAuth2 Applications
- Redirect URI: `https://drone.yourdomain.com/login`
- Copy Client ID and Secret

**3. Start Drone**:
```bash
docker-compose up -d
```

### Drone Pipeline Configuration

`.drone.yml`:

```yaml
kind: pipeline
type: docker
name: default

steps:
  # Test
  - name: test
    image: golang:1.21
    commands:
      - go mod download
      - go test -v -race ./...
      - go vet ./...

  # Build binary
  - name: build
    image: golang:1.21
    commands:
      - CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o safeshare-amd64 ./cmd/safeshare
      - CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o safeshare-arm64 ./cmd/safeshare

  # Build and push Docker image
  - name: docker-build
    image: plugins/docker
    settings:
      registry: gitea.yourdomain.com
      repo: gitea.yourdomain.com/yourusername/safeshare
      tags:
        - latest
        - ${DRONE_COMMIT_SHA:0:8}
      username:
        from_secret: gitea_username
      password:
        from_secret: gitea_token
    when:
      branch:
        - main

  # Build multi-arch on tags
  - name: docker-multiarch
    image: plugins/docker
    settings:
      registry: gitea.yourdomain.com
      repo: gitea.yourdomain.com/yourusername/safeshare
      tags:
        - ${DRONE_TAG}
        - latest
      platforms:
        - linux/amd64
        - linux/arm64
      username:
        from_secret: gitea_username
      password:
        from_secret: gitea_token
    when:
      event:
        - tag

  # Create Gitea release
  - name: release
    image: plugins/gitea-release
    settings:
      base_url: https://gitea.yourdomain.com
      api_key:
        from_secret: gitea_token
      title: ${DRONE_TAG}
      note: |
        ## Docker Image

        Pull the image:
        ```bash
        docker pull gitea.yourdomain.com/yourusername/safeshare:${DRONE_TAG}
        ```
    when:
      event:
        - tag

trigger:
  branch:
    - main
    - develop
  event:
    - push
    - tag
```

### Add Secrets to Drone

```bash
# Via Drone CLI
drone secret add \
  --repository yourusername/safeshare \
  --name gitea_username \
  --data yourusername

drone secret add \
  --repository yourusername/safeshare \
  --name gitea_token \
  --data your-personal-access-token

# Or via Drone UI:
# Drone → Repository → Settings → Secrets
```

### Usage

```bash
# Pull from Gitea Container Registry
docker pull gitea.yourdomain.com/yourusername/safeshare:latest

# Authenticate
docker login gitea.yourdomain.com -u USERNAME -p ACCESS_TOKEN

# Run
docker run -d -p 8080:8080 gitea.yourdomain.com/yourusername/safeshare:latest
```

---

## Multi-Architecture Builds

Build for both x86_64 (amd64) and ARM (arm64) to support:
- Cloud servers (amd64)
- Raspberry Pi, ARM servers (arm64)
- Apple Silicon Macs (arm64)

### Using Docker Buildx

```bash
# Create buildx builder
docker buildx create --name multiarch --use

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag yourusername/safeshare:latest \
  --push \
  .

# List platforms
docker buildx ls
```

### Dockerfile Optimization for Multi-Arch

Ensure your Dockerfile works for both architectures:

```dockerfile
# Multi-stage build
FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS builder

# Build arguments for cross-compilation
ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build for target platform
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w" -o safeshare ./cmd/safeshare

# Runtime image
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/safeshare /app/safeshare
COPY --from=builder /build/internal/static /app/internal/static

RUN adduser -D -u 1000 safeshare && \
    chown -R safeshare:safeshare /app

USER safeshare

EXPOSE 8080

CMD ["/app/safeshare"]
```

---

## Automated Testing

### Unit Tests

```bash
# Run all tests
go test ./...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# With race detection
go test -race ./...

# Verbose output
go test -v ./...
```

### Integration Tests

`tests/integration_test.go`:

```go
//go:build integration
// +build integration

package tests

import (
    "net/http"
    "testing"
)

func TestHealthEndpoint(t *testing.T) {
    resp, err := http.Get("http://localhost:8080/health")
    if err != nil {
        t.Fatalf("Health check failed: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Errorf("Expected status 200, got %d", resp.StatusCode)
    }
}
```

Run with:
```bash
# Start SafeShare in background
docker run -d --name safeshare-test -p 8080:8080 safeshare:latest

# Run integration tests
go test -tags=integration ./tests/...

# Cleanup
docker stop safeshare-test && docker rm safeshare-test
```

---

## Security Scanning

### Container Scanning with Trivy

Add to GitHub Actions:

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
    format: 'sarif'
    output: 'trivy-results.sarif'

- name: Upload Trivy results to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: 'trivy-results.sarif'
```

Manual scan:
```bash
# Scan local image
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image safeshare:latest

# Scan with severity threshold
docker run --rm aquasec/trivy image \
  --severity HIGH,CRITICAL \
  safeshare:latest
```

### Go Security Scanning with Gosec

Add to CI:

```yaml
- name: Run Gosec security scanner
  uses: securego/gosec@master
  with:
    args: './...'
```

Manual scan:
```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run scan
gosec ./...
```

### Dependency Scanning

```bash
# Check for known vulnerabilities
go list -json -deps ./... | nancy sleuth

# Or use govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

---

## Complete CI/CD Workflow Example

Combining testing, building, scanning, and deployment:

`.github/workflows/complete.yml`:

```yaml
name: Complete CI/CD Pipeline

on:
  push:
    branches: [main, develop]
    tags: ['v*.*.*']
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Run tests
        run: go test -v -race -coverprofile=coverage.txt ./...

      - name: Run gosec
        uses: securego/gosec@master
        with:
          args: './...'

      - name: Upload coverage
        uses: codecov/codecov-action@v3

  build:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      security-events: write

    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3

      - name: Log in to registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: ${{ github.event_name != 'pull_request' }}
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Run Trivy scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

  release:
    needs: build
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    permissions:
      contents: write

    steps:
      - uses: actions/checkout@v4

      - name: Create release
        uses: softprops/action-gh-release@v1
        with:
          generate_release_notes: true
```

---

## Next Steps

1. Choose your platform (GitHub, GitLab, or Gitea)
2. Copy the appropriate workflow configuration
3. Add required secrets (registry credentials)
4. Push code and watch the pipeline run
5. Tag a release to trigger multi-arch builds

**See also**:
- [VERSION_STRATEGY.md](./VERSION_STRATEGY.md) - Version management guide
- [PRODUCTION.md](./PRODUCTION.md) - Deployment guide
- [SECURITY_AUDIT.md](./SECURITY_AUDIT.md) - Security checklist
