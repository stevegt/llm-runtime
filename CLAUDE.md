# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**llm-runtime** is a secure command interpreter that enables Large Language Models to interact with local filesystems and execute sandboxed commands. It parses special XML-like commands from LLM output (`<open>`, `<write>`, `<exec>`, `<search>`) and executes them with security constraints including path validation, Docker isolation, and audit logging.

## Development Guidelines

**Documentation and Code Style**:
- Do not use icons, emoji, or decorative Unicode characters in documentation or code unless specifically requested
- Keep documentation clear, concise, and professional
- Use standard ASCII characters for all technical content

## Development Commands

### Building
```bash
# Build the binary
make build

# Build for all platforms
make build-all
```

### Testing
```bash
# Run all tests
make test

# Run tests with coverage report
make test-coverage

# Run comprehensive test suite (includes security tests)
make test-suite

# Test specific features
make test-write        # Test write functionality
make test-exec         # Test exec functionality (requires Docker)
make quick-test        # Quick smoke test

# Run benchmarks
make bench
```

### Running
```bash
# Run interactively
make run

# Run with exec commands enabled
./llm-runtime --interactive --exec-enabled

# Pipe mode (default)
echo "Let me check: <open README.md>" | ./llm-runtime

# File mode
./llm-runtime --input input.txt --output results.txt
```

### Demos and Examples
```bash
make demo              # Basic demo
make exec-demo         # Exec command demo
make example           # Example usage script
```

### Docker and I/O Containerization
```bash
# Check Docker availability
make check-docker

# Build Docker image for containerized I/O
make build-io-image

# Test containerized I/O
make test-io-container
```

### Code Quality
```bash
# Format code
make fmt

# Run go vet
make vet

# Run all quality checks (fmt + vet + test)
make quality
```

### Search Index Management
```bash
# Rebuild search index
./llm-runtime --reindex

# Check Ollama status
./llm-runtime check-ollama

# Validate search index
./llm-runtime search-validate

# Update specific files in index
./llm-runtime search-update <filepath>
```

## Architecture Overview

### Core Design Pattern: State Machine Scanner

The project uses a **state-machine based parser** (not regex) for robust command detection. This is critical because commands like `<write>...</write>` require context-sensitive parsing that regex cannot handle correctly.

**Scanner States** (see `pkg/scanner/scanner.go`):
- `StateScanning` - Default: scanning for commands
- `StateTagOpen` - Detected '<', determining tag type
- `StateOpen` - Parsing `<open filepath>`
- `StateWrite` - Parsing `<write filepath>` tag
- `StateWriteBody` - Accumulating content until `</write>`
- `StateExec` - Parsing `<exec command>`
- `StateExecBody` - Accumulating exec stdin content
- `StateSearch` - Parsing `<search query>`

### Package Organization

```
llm-runtime/
├── cmd/llm-runtime/       # Entry point (main.go)
├── pkg/                   # Public API (importable by other projects)
│   ├── scanner/           # State-machine command parser
│   ├── evaluator/         # Command execution (open, write, exec, search)
│   └── sandbox/           # Security layer (path validation, Docker isolation)
├── internal/              # Private implementation
│   ├── app/               # Application bootstrap and main run loop
│   ├── cli/               # Cobra CLI and Viper config management
│   ├── config/            # Configuration defaults and types
│   ├── search/            # Semantic search (Ollama embeddings + SQLite)
│   └── session/           # Session management and audit logging
```

### Execution Flow

1. **Input** → Scanner reads from stdin/file
2. **Parse** → State machine extracts commands from text
3. **Validate** → Security checks (path traversal, whitelist, limits)
4. **Execute** → Run command (direct file I/O or Docker container)
5. **Audit** → Log operation to `audit.log`
6. **Output** → Structured result with delimiters

### Security Architecture (Defense in Depth)

**Layer 1: Input Validation** (`pkg/sandbox/path.go`)
- Path canonicalization and symlink resolution
- Directory traversal prevention (blocks `../`, absolute paths)
- Excluded paths (`.git`, `.env`, `*.key`, `*.pem`)

**Layer 2: Resource Limits**
- File size limits (1MB read, 100KB write by default)
- Command timeout (30 seconds default)
- Memory and CPU limits for containers

**Layer 3: Container Isolation** (`pkg/sandbox/container.go`)
- Docker isolation with `--network none`
- Read-only repository mount
- Non-root user (UID 1000)
- Dropped Linux capabilities (`--cap-drop ALL`)
- Command whitelist enforcement

**Layer 4: Audit Trail** (`pkg/sandbox/audit.go`)
- All operations logged with timestamps
- Session tracking for correlation
- Success/failure status and error messages

### Command Types

**`<open filepath>`** (`pkg/evaluator/open.go`)
- Validates path and checks file size
- Reads file contents (with optional containerization)
- Returns contents with line numbers

**`<write filepath>content</write>`** (`pkg/evaluator/write.go`)
- Validates path and extension whitelist
- Creates backups if configured
- Auto-formats Go and JSON files
- Atomic writes using temporary files

**`<exec command>`** (`pkg/evaluator/exec.go`)
- Validates against command whitelist
- Runs in Docker container with resource limits
- Supports stdin: `<exec command>stdin_data</exec>`
- Returns exit code, stdout, stderr, duration

**`<search query>`** (`pkg/evaluator/search.go`)
- Uses Ollama for local embedding generation
- Stores embeddings in SQLite database
- Cosine similarity ranking
- Returns top-K relevant files

## Configuration System

Configuration precedence (lowest to highest):
1. Defaults (`internal/config/defaults.go`)
2. Config file (`llm-runtime.config.yaml`)
3. Command-line flags
4. Environment variables (prefix `LLM_`)

Key configuration sections:
- `repository.root` - Repository root directory
- `repository.excluded_paths` - Paths to exclude
- `commands.exec.whitelist` - Allowed commands for `<exec>`
- `commands.exec.timeout_seconds` - Exec timeout
- `commands.exec.memory_limit` - Container memory limit
- `commands.write.allowed_extensions` - File extensions allowed for writing
- `search.ollama_url` - Ollama API endpoint
- `search.embedding_model` - Embedding model name

## Key Implementation Details

### Why State Machine Over Regex?

The `<write>` command requires context-sensitive parsing because content can contain `</write>` as text. Regular expressions (Type-3 in Chomsky hierarchy) cannot handle this—they lack memory for nested structures. The state machine explicitly tracks state across line boundaries.

**Wrong Approach** (regex breaks on nested content):
```go
writeRegex := regexp.MustCompile(`<write\s+([^>]+)>(.*?)</write>`)
// FAILS: <write f>content with </write> inside</write>
```

**Correct Approach** (state machine):
```go
case StateWriteBody:
    s.buffer.WriteString(line)
    if strings.Contains(line, "</write>") {
        return s.extractWriteCommand()
    }
```

### Single Code Path Principle

All input modes (pipe, interactive, file) use the same `Scanner` and execution pipeline. This ensures consistent behavior and simplifies testing.

### Container Pool Architecture

The container pool optimizes performance by reusing Docker containers:

**Lifecycle**:
1. Pool pre-creates containers on startup (`sleep infinity`)
2. `Get()` acquires an available container (or creates new if pool not full)
3. Command execution via `docker exec` on the running container
4. `Return()` releases container back to pool
5. Containers are recycled after max uses or health check failures
6. Idle containers (>5 min) are automatically cleaned up

**Benefits**:
- Eliminates 1-3s Docker startup latency per command
- Maintains security isolation (each container still isolated)
- Automatic health monitoring and recovery
- Resource-bounded (configurable pool size)

**Trade-offs**:
- Containers have read-write access to repository (vs read-only for single-use)
- Memory overhead from idle containers
- Complexity in lifecycle management

### Security Model: Container-Based Isolation

**Critical Concept**: The container is the security boundary. Per the executor comments in `pkg/evaluator/executor.go`:
- All mounted repository contents are considered sacrificial on compromise
- No path-level validation within the container
- LLM has unrestricted filesystem access inside the container
- Symlinks treated as normal filesystem objects
- Host protected by container namespace isolation

### Error Handling

Commands fail gracefully—one command error doesn't crash the session. Errors are categorized:
- `SYNTAX` - Malformed command
- `VALIDATION` - Security check failed
- `EXECUTION` - Runtime failure
- `RESOURCE` - Limit exceeded

### Semantic Search Implementation

**Indexing Flow**:
1. Walk repository files (respecting exclusions)
2. Generate embeddings via Ollama API (`nomic-embed-text`)
3. Store in SQLite with content hash for change detection
4. Index is persistent across runs

**Search Flow**:
1. Query → Ollama → Query embedding
2. Compute cosine similarity with all file embeddings
3. Return top-K results sorted by relevance

**Why local embeddings?**
- Privacy: code never leaves machine
- Speed: no network latency
- Cost: no API fees
- Offline: works without internet

## Testing Strategy

**Unit Tests**: Test individual functions (`*_test.go` next to source)

**Integration Tests**: Test component interaction

**Security Tests**: Test sandbox boundaries (see `scripts/security_test.sh`)
- Path traversal attempts
- Command whitelist violations
- Resource limit enforcement
- Extension validation

**Running Specific Tests**:
```bash
# Run tests for a specific package
go test -v ./pkg/scanner
go test -v ./pkg/evaluator

# Run a specific test function
go test -v -run TestScanner ./pkg/scanner
go test -v -run TestPathValidation ./pkg/sandbox

# Run with race detection
go test -race ./...
```

**Key Test Files**:
- `pkg/sandbox/path_test.go` - Path validation tests
- `pkg/sandbox/exec_validation_test.go` - Command whitelist tests
- `pkg/sandbox/pool_test.go` - Container pool tests
- `pkg/scanner/scanner_test.go` - Parser tests
- `pkg/evaluator/*_test.go` - Command execution tests

## Common Development Patterns

### Adding a New Command Type

1. Define state in `pkg/scanner/scanner.go` (e.g., `StateNewCmd`)
2. Add parsing logic in scanner state machine
3. Create `pkg/evaluator/newcmd.go` with execution handler
4. Add security validation in `pkg/sandbox/`
5. Register in executor dispatch
6. Add tests in `pkg/evaluator/newcmd_test.go`
7. Update documentation

### Modifying Security Rules

- Path exclusions: Edit `internal/config/defaults.go` → `excluded_paths`
- Command whitelist: Edit `internal/config/defaults.go` → `exec.whitelist`
- Extension whitelist: Edit `pkg/sandbox/extension.go`
- Resource limits: Edit flags or config file

### Working with Docker

**Container Pool** (see `pkg/sandbox/pool.go`):
- The project uses container pooling to eliminate Docker startup latency
- Containers are pre-warmed and reused across multiple commands
- Each container has a usage limit and is recycled after max uses
- Idle containers are cleaned up after 5 minutes of inactivity
- Health checks run periodically to verify container state
- Pool configuration: size, max uses, idle timeout, health check interval

**Container Configuration**:
- Default image: `ubuntu:22.04`
- Custom image: Use `--exec-image` flag or config
- Container lifecycle: Pooled (reused) or ephemeral (for one-off commands)
- Network: Always disabled (`--network none`)
- Filesystem: Repository mounted at `/workspace` (read-write for pooled containers)
- Security: User 1000:1000, all capabilities dropped, no new privileges

**Key Implementation**:
- `RunContainer()` - Single-use container execution
- `ContainerPool.Get()` - Acquire container from pool
- `ContainerPool.Return()` - Return container to pool (or recycle if exhausted)
- Pooled containers run `sleep infinity` and execute commands via `docker exec`

## Debugging

**Verbose Mode**: Shows configuration and execution details
```bash
./llm-runtime --verbose --interactive
```

**Audit Log**: Check `audit.log` for operation history
```bash
tail -f audit.log
```

**Test Specific Command**:
```bash
echo "<open README.md>" | ./llm-runtime --verbose
```

**Docker Issues**:
```bash
make check-docker           # Verify Docker availability
docker ps -a                # Check container status
docker logs <container_id>  # View container logs
```

## Performance Characteristics

| Operation | Typical Time | Notes |
|-----------|--------------|-------|
| Command parsing | <1ms | State machine is fast |
| Path validation | <1ms | Already optimized |
| File read (1MB) | <10ms | SSD dependent |
| Docker startup (cold) | 1-3s | Single-use container |
| Docker exec (warm) | 50-200ms | Pooled container (90% faster) |
| Ollama embedding | 100-500ms | First query slower (model load) |
| Similarity search | <1ms per file | SQLite is efficient |

**Container Pool Statistics**:
Check pool performance with `pool.Stats()`:
- `pool_hits` - Commands served from pool
- `pool_misses` - New containers created
- `containers_created` / `containers_destroyed` - Lifecycle metrics

## Output Format

The tool produces structured output with clear delimiters:

```
=== LLM TOOL START ===
=== COMMAND: <type argument> ===
[command-specific output]
=== END COMMAND ===
=== LLM TOOL COMPLETE ===
```

This allows LLMs to reliably parse results and understand command outcomes.

## Important Gotchas

1. **Docker Required for Exec**: The `<exec>` command requires Docker to be running
2. **Ollama Required for Search**: Semantic search needs Ollama with `nomic-embed-text` model
3. **Extension Whitelist**: Writing to new file types requires updating allowed extensions
4. **Repository Isolation**: The `--root` flag sets the working directory AND security boundary - all file operations are relative to this root
5. **Command Whitelist**: New exec commands must be added to whitelist
6. **State Machine Parsing**: Don't use regex for new command types—extend the state machine
7. **Atomic Writes**: Write operations use temp files and rename for atomicity
8. **Resource Limits**: Container limits are enforced—long-running commands will timeout
9. **Container Pool Security**: Pooled containers have read-write access to repository (trade-off for performance)
10. **Idle Cleanup**: Containers idle for >5 minutes are automatically destroyed to free resources
