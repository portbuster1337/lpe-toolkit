# Linux LPE Toolkit

Multi-architecture privilege escalation toolkit with 29 exploits (amd64 pre-built; other architectures compiled via gcc at runtime). Supports amd64, arm64, 386, mips, mipsle, mips64, and mips64le. Detects kernel version, filters patched exploits, and tries each in order until root is obtained.

## Quick Start

```bash
# run directly (no gcc needed on target if pre-compiled binaries are embedded)
./lpe-toolkit

# dry-run: show exploit plan without executing
./lpe-toolkit --dry-run

# skip specific exploits
./lpe-toolkit --skip "dirtyfrag,dirtypipe"

# execute a command once root is achieved and show its output
./lpe-toolkit -c "id"

# silent automation: suppress all output except the command result
./lpe-toolkit -q -c "whoami"

# verbose output (includes exploit stdout/stderr)
./lpe-toolkit -v
```

## Usage

| Flag | Description |
|------|-------------|
| `--dry-run` | Show which exploits are available/skipped |
| `--just-build` | Resolve all exploits, print paths, exit (useful for packaging) |
| `--skip LIST` | Comma-separated exploit names to skip |
| `-c`, `--command CMD` | Execute CMD as root instead of spawning an interactive shell |
| `-q`, `--quiet` | Suppress toolkit messages; only show root shell output or `unsuccessful in getting root` |
| `-v`, `--verbose` | Include exploit stdout/stderr in output (mutually exclusive with `-q`) |

**Note:** `-v` and `-q` are mutually exclusive — the toolkit exits with an error if both are specified.

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
| 8 | CIFSwitch `CVE-2026-46243` | cifs.spnego + NSS namespace confusion | pre-built / compile |
| 9 | PwnKit `CVE-2021-4034` | pkexec environment escape | pre-built / compile |
| 10 | OverlayFS `CVE-2021-3493` | user-ns mount escape | pre-built / compile |
| 11 | OvFS+FUSE `CVE-2023-0386` | FUSE mount escape | pre-built / compile |
| 12 | Pack2TheRoot `CVE-2026-41651` | PackageKit D-Bus race → setuid root | pre-built / compile |
| 13 | Polkit D-Bus `CVE-2021-3560` | accounts-daemon race | pre-built / compile |
| 14 | Docker Socket | writable /var/run/docker.sock | pre-built / compile |
| 15 | netfilter OOB `CVE-2021-22555` | ip_tables corruption | pre-built / compile |
| 16 | nft UAF2 `CVE-2022-2586` | nftables chain UAF | pre-built / compile |
| 17 | pidfd race `CVE-2026-46333` | ssh-keysign/shadow FD theft | pre-built / compile |
| 18 | CPU Timer Race `CVE-2025-38352` | POSIX timer race (PoC) | pre-built / compile |
| 19 | nft UAF `CVE-2024-1086` | Notselwyn multi-file nftables | pre-built / compile |
| 20 | PEdit COW `CVE-2026-46331` | tc-pedit page-cache overwrite su | pre-built / compile |
| 21 | DirtyClone `CVE-2026-43503` | ESP-in-UDP TEE page-cache passwd | pre-built / compile |
| 22 | Bad Epoll `CVE-2026-46242` | epoll close-vs-close race UAF | pre-built / compile |
| 23 | FUSE OOB `CVE-2026-31694` | FUSE readdir cache OOB -> passwd | pre-built / compile |
| 24 | RefluXFS `CVE-2026-64600` | XFS reflink CoW race -> passwd overwrite | pre-built / compile |
| 25 | CrackArmor `CVE-2026-23268+` | AppArmor confused-deputy -> sudo root | pre-built / compile |
| 26 | skb_shift `CVE-2026-43503` | TCP SACK flag loss -> ESP page-cache su | pre-built / compile |
| 27 | GRO Flag Loss `CVE-2026-43503` | GRO coalesce flag loss -> ESP page-cache su | pre-built / compile |
| 28 | snap-confine `CVE-2026-8933` | set-cap race -> udev rule -> setuid bash | pre-built / compile |
| 29 | GTFOBins | 80+ passwordless sudo techniques | go-handler |

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

Requirements: Go 1.21+, gcc, and cross-compilers for target architectures:
- **arm64**: `aarch64-linux-gnu-gcc`
- **386**: `i686-linux-gnu-gcc`
- **mips**: `mips-linux-gnu-gcc`
- **mipsle**: `mipsel-linux-gnu-gcc`
- **mips64**: `mips64-linux-gnuabi64-gcc`
- **mips64le**: `mips64el-linux-gnuabi64-gcc`

## Pre-Compiled Binary Packaging

The `--just-build` flag resolves all usable exploits and prints their paths. Use it to verify what will be available at runtime.

The pre-compiled binary archive for each release includes a statically linked Go binary with embedded C exploits. All exploits are pre-compiled for all architectures.

## Architecture

- **`toolkit.go`**: Core exploit definitions, kernel version parsing, binary resolution, GTFOBins sudo abuse handler, `execCommandAsRoot()` for non-interactive command execution, `msg()`/`say()` verbosity helpers
- **`main.go`**: CLI entry point with flags (`-c`, `-q`, `-v`, `--skip`, `--dry-run`, `--just-build`) and signal handling
- **`build-exploits.sh`**: Cross-compilation script for C exploits
- **`exploits/`**: C source files and pre-compiled binaries embedded via `//go:embed`

### Notable Changes
- **cve_2026_41651.c**: Added Pack2TheRoot — raw D-Bus client (no libdbus) races PackageKit `InstallFiles` SIMULATE/NONE flags to trigger root-privileged postinst execution, drops setuid-root bash at `/var/tmp/.suid_bash`

- `parseKernelVersion` fixed: added `parseIntPrefix` to handle `-rcN` suffixes when comparing kernel versions
- `bad_epoll.c` rewritten with correct J-jaeyoung architecture: two epoll pairs, timerfd IRQ widening via 3000+ waiters, depth-3 oracle, acquire/release atomics on shared variables
- All exploits (including leak-only/PoC-only) now spawn a root shell or execute the requested command
- **cve_2026_46333.c**: Added `try_passwd_root()` — steals writable `/etc/shadow` fd from `passwd`, writes a known password hash, then spawns `su -`; falls back to leak-only methods
- **cve_2025_38352.c**: Added dirtypipe-style `splice()` overwrite of `/etc/passwd` → `root::0:0:` → spawns `su -`
- **Command mode**: Page-cache exploits use `--corrupt-only` to skip the interactive PTY bridge (also honored by `refluxfs`, `crackarmor`, `skbshift`, `groflag`, `snapconfine`); `execCommandAsRoot()` pipes the command to `su` stdin for shellcode-patched binaries (or `SuStdin`-flagged marker exploits), tries `su - -c` with an empty password for passwd-clearing exploits (RefluXFS), then a setuid helper shell (`/var/tmp/.suid_bash`, `/var/tmp/cifswitch_rootsh`), then falls back to `sudo -n`

### New Exploits Added
- **peditcow.c** (CVE-2026-46331): tc-pedit page-cache write primitive overwrites su ELF entry with shellcode. v5.18–v7.1-rc6. Unprivileged user+net namespace gives CAP_NET_ADMIN.
- **dirtyclone.c** (CVE-2026-43503): DirtyClone Python port to C. ESP-in-UDP TEE netfilter target corrupts /etc/passwd. Self-contained AES-128-CBC implementation. v7.1-rc1–rc4.
- **bad_epoll.c** (CVE-2026-46242): Bad Epoll close-vs-close race UAF. **Target-specific**: default offsets target lts-6.12.67 (kernelCTF). Customize `OFF_*` and `PIVOT*` defines for your kernel. Requires /proc/kallsyms (kptr_restrict=0). Run on an **unpatched kernel** — the fix (commit `a6dc643c6931`, adds `ep_clear_and_put`) was backported to many distros including Ubuntu 22.04's 6.8 HWE.
- **cve_2026_31694.c** (CVE-2026-31694): FUSE readdir cache OOB write. Overflows 24 bytes into adjacent page-cache page to make /etc/passwd root passwordless. v6.15+. Requires fusermount3.

### 2026 LPEs added (all end-to-end, no per-target grooming)
- **refluxfs** (CVE-2026-64600): XFS reflink CoW race clears the root password in seconds (Qualys PoC); `-c` runs commands via empty-password `su`.
- **crackarmor** (CVE-2026-23268+): AppArmor confused-deputy loads a sudo profile denying `CAP_SETUID`, triggering the sudo+Postfix fail-open to root; `-c` runs via `sudo -n`. Kernel-space paths (UAF/double-free) need per-target grooming and are not included.
- **skbshift** (CVE-2026-43503 TCP-SACK variant): missing `SKBFL_SHARED_FRAG` propagation in `skb_shift()` bypasses the Dirty Frag/Fragnesia patches; deterministic ESP-in-TCP byte-at-a-time su overwrite (~10s, v3.9–v7.1-rc4, all distros). `-c` runs via piped `su` (`SuStdin`).
- **groflag** (CVE-2026-43503 GRO variant): same primitive via `skb_gro_receive()` over veth; working PoC with in-loop verify (retry on partial write); also a container-escape angle. `-c` via piped `su`.
- **snapconfine** (CVE-2026-8933): set-capabilities snap-confine + FUSE/symlink/chmod races → udev `PROGRAM` rule → root command exec dropping a setuid bash; `-c` runs via the new setuid-helper fallback (also fixes `-c` for Pack2TheRoot/CIFSwitch helpers). Needs Ubuntu with set-cap snap-confine + firefox snap + FUSE + udevd.

Deliberately excluded: CVE-2026-80844/81000/68121/74469 (only heavily-groomed, target-pinned PoCs exist — exact kernels, vCPU/RAM shapes, destructive), CVE-2026-53362 (working chain needs `CAP_NET_RAW` + KVM/amdgpu stages; Debian/Ubuntu default is DoS-only), CVE-2026-53266 (no public weaponization), CVE-2026-3888 (10–30 day time-gated trigger).
