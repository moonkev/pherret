# pherret

Scan open file descriptors across processes, filter by regex, and print process metadata.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## What it prints per match

- process owner UID and username
- process PID
- process current working directory
- process executable
- matching file descriptor and open path

## Run

> **Note:** Always use `go run .` (not `go run main.go`) — the implementation is split across multiple files in the package.

```sh
go run . -regex '/var/log/.*'
```

JSON output:

```sh
go run . -regex '/home/.*/\\.ssh/.*' -json
```

## Backend by OS

- Linux: scans `/proc/<pid>/fd` and reads process metadata from `/proc/<pid>/status`, `/proc/<pid>/cwd`, and `/proc/<pid>/exe`.
- macOS: uses native Apple `libproc` APIs (`proc_pidinfo`, `proc_pidpath`) via CGo — no external tools required.
- Other OSes: currently unsupported, but the scanner is now split so additional backends can be added cleanly.

Implementation is split into separate files with Go build tags:

- `scanner_linux.go`
- `scanner_darwin.go`
- `scanner_unsupported.go`
- `scanner_types.go`

## Notes

- As non-root, some processes may be skipped or partially visible due to permissions.
- macOS backend uses CGo and requires the standard Xcode Command Line Tools (`xcode-select --install`) to build — no other dependencies needed at runtime.

