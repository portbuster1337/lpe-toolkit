//go:build 386

package main

import "embed"

//go:embed exploits/bin/386
var precompiledFS embed.FS
