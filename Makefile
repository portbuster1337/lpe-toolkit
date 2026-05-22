.PHONY: all build clean build-exploits

LDFLAGS = -ldflags="-s -w"

all: build-exploits
	go build $(LDFLAGS) -o lpe-toolkit .

# Build pre-compiled exploits then embed them in the Go binary
build: build-exploits
	go build $(LDFLAGS) -o lpe-toolkit .

# Cross-compile for all arches
build-all: build-exploits
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o lpe-toolkit-amd64 .
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o lpe-toolkit-arm64 .
	GOOS=linux GOARCH=386 go build $(LDFLAGS) -o lpe-toolkit-386 .
	GOOS=linux GOARCH=mips go build $(LDFLAGS) -o lpe-toolkit-mips .
	GOOS=linux GOARCH=mipsle go build $(LDFLAGS) -o lpe-toolkit-mipsle .
	GOOS=linux GOARCH=mips64 go build $(LDFLAGS) -o lpe-toolkit-mips64 .
	GOOS=linux GOARCH=mips64le go build $(LDFLAGS) -o lpe-toolkit-mips64le .

# Compile C exploits for the native arch
build-exploits:
	./build-exploits.sh

# Run without pre-compiled binaries (compile on target)
run-source:
	go run .

clean:
	rm -f lpe-toolkit lpe-toolkit-* 2>/dev/null || true
	rm -rf exploits/bin/amd64 exploits/bin/arm64 exploits/bin/386 exploits/bin/mips exploits/bin/mipsle exploits/bin/mips64 exploits/bin/mips64le
