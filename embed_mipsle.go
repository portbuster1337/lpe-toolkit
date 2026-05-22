//go:build mipsle

package main

import "embed"

//go:embed exploits/bin/mipsle
var precompiledFS embed.FS
