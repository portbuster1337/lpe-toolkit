//go:build mips

package main

import "embed"

//go:embed exploits/bin/mips
var precompiledFS embed.FS
