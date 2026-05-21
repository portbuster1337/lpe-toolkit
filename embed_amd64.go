//go:build amd64

package main

import "embed"

//go:embed exploits/bin/amd64
var precompiledFS embed.FS
