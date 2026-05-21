# Linux LPE Toolkit

Multi-architecture privilege escalation toolkit with 18 pre-built and runtime-compilable exploits. Detects kernel version, filters patched exploits, and tries each in order until root is obtained.

## Quick Start

```bash
# run directly (no gcc needed on target if pre-compiled binaries are embedded)
./lpe-toolkit

# dry-run: show exploit plan without executing
./lpe-toolkit --dry-run

# skip specific exploits
./lpe-toolkit --skip "dirtyfrag,dirtypipe"

# verbose output
./lpe-toolkit -v
```

## Usage

| Flag | Description |
|------|-------------|
| `--dry-run` | Show which exploits are available/skipped |
| `--just-build` | Resolve all exploits, print paths, exit (useful for packaging) |
| `--skip LIST` | Comma-separated exploit names to skip |
| `-v` | Verbose logging |

## Exploits

| # | Name | Target | Type |
|---|------|--------|------|
| 1 | Copy Fail `CVE-2026-31431` | AF_ALG + splice page-cache write | pre-built / compile |
| 2 | Dirty Frag `CVE-2026-43284` | xfrm-ESP/RxRPC page-cache write | pre-built / compile |
| 3 | Fragnesia `CVE-2026-46300` | espintcp splice page-cache corruption | pre-built / compile |
| 4 | DirtyDecrypt `CVE-2026-31635` | rxgk pagecache write | pre-built / compile |
| 5 | Fragnesia v2 | skb_segment GRO coalesce | pre-built / compile |
| 6 | PinTheft | RDS zerocopy + io_uring page-cache overwrite | pre-built / compile |
| 7 | Dirty Pipe `CVE-2022-0847` | /etc/passwd page-cache overwrite | pre-built / compile |
| 8 | PwnKit `CVE-2021-4034` | pkexec environment escape | pre-built / compile |
| 9 | OverlayFS `CVE-2021-3493` | user-ns mount escape | pre-built / compile |
| 10 | OvFS+FUSE `CVE-2023-0386` | FUSE mount escape | pre-built / compile |
| 11 | Polkit D-Bus `CVE-2021-3560` | accounts-daemon race | pre-built / compile |
| 12 | Docker Socket | writable /var/run/docker.sock | pre-built / compile |
| 13 | netfilter OOB `CVE-2021-22555` | ip_tables corruption | pre-built / compile |
| 14 | nft UAF2 `CVE-2022-2586` | nftables chain UAF | pre-built / compile |
| 15 | pidfd race `CVE-2026-46333` | ssh-keysign/shadow FD theft | pre-built / compile |
| 16 | CPU Timer Race `CVE-2025-38352` | POSIX timer race (PoC) | pre-built / compile |
| 17 | nft UAF `CVE-2024-1086` | Notselwyn multi-file nftables | pre-built / compile |
| 18 | GTFOBins | 80+ passwordless sudo techniques | go-handler |

## Build from Source

```bash
# native build (pre-compile C exploits then embed in Go binary)
make

# cross-compile for all architectures (native arch's C exploits only)
make build-all

# run directly from source (compile exploits on target at runtime)
make run-source

# clean build artifacts
make clean
```

Requirements: Go 1.21+, gcc, and cross-compilers for arm64/aarch64-linux-gnu-gcc and 386/i686-linux-gnu-gcc.

## Pre-Compiled Binary Packaging

The `--just-build` flag resolves all usable exploits and prints their paths. Use it to verify what will be available at runtime.

The pre-compiled binary archive for each release includes a statically linked Go binary with embedded C pre-compiled for all three architectures (amd64, arm64, 386).

## Architecture

- **`toolkit.go`**: Core exploit definitions, kernel version parsing, binary resolution, GTFOBins sudo abuse handler
- **`main.go`**: CLI entry point with flags and signal handling
- **`build-exploits.sh`**: Cross-compilation script for C exploits
- **`exploits/`**: C source files and pre-compiled binaries embedded via `//go:embed`
