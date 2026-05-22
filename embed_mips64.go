//go:build mips64

package main

import "embed"

//go:embed exploits/bin/mips64
var precompiledFS embed.FS
