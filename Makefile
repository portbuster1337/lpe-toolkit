.PHONY: all build clean build-exploits

all: build-exploits
	go build -o lpe-toolkit .

# Build pre-compiled exploits then embed them in the Go binary
build: build-exploits
	go build -o lpe-toolkit .

# Cross-compile for all 3 arches (pre-compiled exploits only for native arch)
build-all: build-exploits
	GOOS=linux GOARCH=amd64 go build -o lpe-toolkit-amd64 .
	GOOS=linux GOARCH=arm64 go build -o lpe-toolkit-arm64 .
	GOOS=linux GOARCH=386 go build -o lpe-toolkit-386 .

# Compile C exploits for the native arch
build-exploits:
	./build-exploits.sh

# Run without pre-compiled binaries (compile on target)
run-source:
	go run .

clean:
	rm -f lpe-toolkit lpe-toolkit-* exploits/bin/*.amd64 exploits/bin/*.arm64 exploits/bin/*.386 2>/dev/null || true
