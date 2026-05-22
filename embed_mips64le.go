//go:build mips64le

package main

import "embed"

//go:embed exploits/bin/mips64le
var precompiledFS embed.FS
