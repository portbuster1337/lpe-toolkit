package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var verbose bool
	var quiet bool
	var command string
	var skipList string
	var dryRun bool
	var justBuild bool
	flag.BoolVar(&verbose, "v", false, "verbose output (includes exploit stdout/stderr)")
	flag.BoolVar(&quiet, "q", false, "quiet mode: suppress all output except root shell or failure message")
	flag.StringVar(&command, "c", "", "command to execute once root is achieved (output will be shown)")
	flag.StringVar(&command, "command", "", "command to execute once root is achieved (output will be shown)")
	flag.StringVar(&skipList, "skip", "", "comma-separated exploits to skip")
	flag.BoolVar(&dryRun, "dry-run", false, "show exploit plan without running")
	flag.BoolVar(&justBuild, "just-build", false, "compile/setup all exploits then exit (useful for packaging)")
	flag.Parse()

	if verbose && quiet {
		fmt.Fprintln(os.Stderr, "[-] Cannot specify both -v and -q")
		os.Exit(1)
	}

	skipped := make(map[string]bool)
	if skipList != "" {
		for _, s := range splitComma(skipList) {
			skipped[s] = true
		}
	}

	tk := NewToolkit(verbose, quiet, command, skipped)

	if dryRun {
		tk.PrintPlan()
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Interrupted, cleaning up...")
		tk.Cleanup()
		os.Exit(130)
	}()

	if justBuild {
		tk.JustBuild()
		return
	}

	tk.Run()
}

func splitComma(s string) []string {
	var r []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				r = append(r, s[start:i])
			}
			start = i + 1
		}
	}
	return r
}
