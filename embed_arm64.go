//go:build arm64

package main

import "embed"

//go:embed exploits/bin/arm64
var precompiledFS embed.FS
