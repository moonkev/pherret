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

## Commands

pherret provides two commands:

- `list` — scan once and print all matches.
- `watch` — scan continuously on an interval, printing only matches not already seen (see [Deduplication](#deduplication)).

**NOTE:** `watch` is not a "live" watch; it polls the system at a fixed interval,
so there may be a delay between when a file is opened and when it is reported.
In addition, `watch` will not catch files that are opened and closed between scan intervals.
To do this would require a kernel-level file system watch or tracing all processes on the system, which is outside the scope of this tool.

```
pherret list [flags]
pherret watch [flags]

Flags:
  -r, --regex string        Regex to filter open file paths (default "/", i.e. match everything)
  -f, --format string       Output format: table, json, otlp (default "table")
  -s, --show-skipped        Print a note to stderr with the number of processes skipped due to permission or read errors
  -i, --interval duration   (watch only) Polling interval between scans (default 2s)
  -h, --help                help for the command
```

### Examples

```sh
# Find all open files under /var/log
pherret list -r '/var/log/.*'

# Find SSH-related open files, output as JSON
pherret list -r '/\.ssh/.*' -f json

# Continuously watch for newly opened files in /tmp, checking every second
pherret watch -r '/tmp/.*' -i 1s
```

### Deduplication

`watch` computes a hash of each match (uid, user, pid, cwd, exe, fd, path) and caches it in memory. On each scan, only matches whose hash hasn't been seen before are printed — so a long-running `watch` won't repeatedly print file descriptors that haven't changed. `watch` runs until interrupted (Ctrl+C / `SIGTERM`).

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

## Output formats

### table / json

The default `table` format and the `json` format require no additional configuration; they write to stdout.

### otlp

The `otlp` format exports each match as an OpenTelemetry log record via the OTLP protocol. It is configured entirely through flags (available on both `list` and `watch`):

| Flag | Description |
|---|---|
| `--otlp-endpoint` | Collector address, e.g. `localhost:4317` (grpc) or `localhost:4318` (http). **Required** when `--format=otlp`. No scheme. |
| `--otlp-protocol` | Transport: `grpc` (default) or `http`. |
| `--otlp-url-path` | Overrides the request path for the `http` protocol, e.g. `/v1/logs`. |
| `--otlp-header` | Additional request header/metadata as `Key=Value`. Repeatable. |
| `--otlp-tls` | Use TLS when connecting to the endpoint (plaintext if omitted). |
| `--otlp-ca-cert` | PEM encoded CA certificate used to verify the server, instead of the system trust store. Requires `--otlp-tls`. |
| `--otlp-client-cert` / `--otlp-client-key` | PEM encoded client certificate/key pair for mutual TLS (mTLS). Both are required together, and require `--otlp-tls`. |
| `--otlp-insecure-skip-verify` | Skip server certificate verification (testing only). Requires `--otlp-tls`. |

```sh
# Plaintext gRPC (default protocol)
pherret list -r '/var/log/.*' -f otlp --otlp-endpoint localhost:4317

# HTTP with TLS and a bearer token header
pherret watch -r '/tmp/.*' -f otlp \
  --otlp-endpoint collector.example.com:4318 \
  --otlp-protocol http \
  --otlp-url-path /v1/logs \
  --otlp-tls \
  --otlp-header 'Authorization=Bearer <token>'

# gRPC with mutual TLS
pherret list -r '/etc/.*' -f otlp \
  --otlp-endpoint collector.example.com:4317 \
  --otlp-tls \
  --otlp-ca-cert /etc/pherret/ca.pem \
  --otlp-client-cert /etc/pherret/client.pem \
  --otlp-client-key /etc/pherret/client-key.pem
```

## Notes

- Running as root gives full visibility across all processes. As a regular user, some processes will be skipped due to permission restrictions.
- Skipped processes are only reported on stderr when `--show-skipped` is passed, and do not cause a non-zero exit.
