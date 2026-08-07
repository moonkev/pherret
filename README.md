# pherret

Scan open file descriptors across all running processes, filter by file path regex, and display process metadata.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Output per match

| Field | Description |
|---|---|
| `UID` | Process owner numeric ID |
| `USER` | Process owner username |
| `PID` | Process ID |
| `CWD` | Process current working directory |
| `EXE` | Process executable path |
| `FD` | File descriptor number |
| `PATH` | Matched open file path |

## Usage

```
pherret scan -r <regex> [flags]

Flags:
  -r, --regex string    Regex to filter open file paths (required)
  -f, --format string   Output format: table, json (default "table")
  -h, --help            help for scan
```

### Examples

```sh
# Find all open files under /var/log
pherret scan -r '/var/log/.*'

# Find SSH-related open files, output as JSON
pherret scan -r '/\.ssh/.*' -f json

# Find open files in /tmp belonging to any process
pherret scan -r '/tmp/.*'
```

## Installation

```sh
git clone https://github.com/moonkev/pherret
cd pherret
go build -o pherret .
```

## Backends

pherret uses OS-native APIs — no external tools required.

| OS | Implementation |
|---|---|
| Linux | Reads `/proc/<pid>/fd`, `/proc/<pid>/status`, `/proc/<pid>/cwd`, `/proc/<pid>/exe` |
| macOS | Calls Apple `libproc` APIs (`proc_pidinfo`, `proc_pidpath`) via CGo |
| Other | Unsupported (additional backends can be added under `internal/scan/`) |

### macOS build requirement

CGo is used for the macOS backend. The standard Xcode Command Line Tools are required to build:

```sh
xcode-select --install
```

## Notes

- Running as root gives full visibility across all processes. As a regular user, some processes will be skipped due to permission restrictions.
- Skipped processes are reported as a note on stderr and do not cause a non-zero exit.
