//go:build linux

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moonkev/pherret/internal/output"
	"github.com/moonkev/pherret/internal/scan"
	"github.com/spf13/cobra"
)

func newTestRoot() *cobra.Command {
	root := &cobra.Command{Use: "pherret"}
	root.AddCommand(newListCmd())
	root.AddCommand(newWatchCmd())
	return root
}

func captureStdout(fn func()) string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func execCmdCtx(ctx context.Context, args ...string) (stdout string, err error) {
	root := newTestRoot()
	root.SetArgs(args)
	stdout = captureStdout(func() {
		err = root.ExecuteContext(ctx)
	})
	return stdout, err
}

func execCmd(args ...string) (stdout string, err error) {
	return execCmdCtx(context.Background(), args...)
}

// --- hashMatch ---

func TestHashMatch_StableForIdenticalMatch(t *testing.T) {
	m := scan.Match{UID: 1000, User: "alice", PID: 42, FD: "3", CWD: "/home/alice", Exe: "/usr/bin/cat", Path: "/tmp/foo.txt"}
	if hashMatch(m) != hashMatch(m) {
		t.Fatal("expected identical matches to hash identically")
	}
}

func TestHashMatch_DiffersForDifferentMatch(t *testing.T) {
	m1 := scan.Match{UID: 1000, PID: 42, FD: "3", Path: "/tmp/foo.txt"}
	m2 := scan.Match{UID: 1000, PID: 42, FD: "4", Path: "/tmp/foo.txt"}
	if hashMatch(m1) == hashMatch(m2) {
		t.Fatal("expected different matches to hash differently")
	}
}

// --- OTLP flags / output.New ---

func TestOTLPFlags_ParsedHeaders(t *testing.T) {
	cmd := &cobra.Command{}
	cfg := addOTLPFlags(cmd)
	if err := cmd.Flags().Parse([]string{
		"--otlp-endpoint", "localhost:4317",
		"--otlp-protocol", "grpc",
		"--otlp-header", "Authorization=Bearer abc",
		"--otlp-tls",
	}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	if cfg.Endpoint != "localhost:4317" {
		t.Errorf("expected endpoint to be set, got %q", cfg.Endpoint)
	}
	if !cfg.TLS {
		t.Errorf("expected TLS to be true")
	}
	headers, err := cfg.ParsedOTLPHeaders()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if headers["Authorization"] != "Bearer abc" {
		t.Errorf("expected header to be parsed, got %v", headers)
	}
}

func TestOTLPFlags_InvalidHeader(t *testing.T) {
	cmd := &cobra.Command{}
	cfg := addOTLPFlags(cmd)
	if err := cmd.Flags().Parse([]string{"--otlp-header", "no-equals-sign"}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	if _, err := cfg.ParsedOTLPHeaders(); err == nil {
		t.Fatal("expected error for malformed header, got nil")
	}
}

func TestOutputNew_OTLPRequiresEndpoint(t *testing.T) {
	cmd := &cobra.Command{}
	otlpCfg := addOTLPFlags(cmd)

	if _, err := output.New("otlp", &output.Config{OTLP: otlpCfg}); err == nil {
		t.Fatal("expected error when --otlp-endpoint is missing, got nil")
	} else if !strings.Contains(err.Error(), "otlp-endpoint") {
		t.Errorf("error should mention otlp-endpoint, got: %v", err)
	}
}

func TestOutputNew_TableDoesNotRequireOTLPFlags(t *testing.T) {
	cmd := &cobra.Command{}
	otlpCfg := addOTLPFlags(cmd)

	formatter, err := output.New("table", &output.Config{OTLP: otlpCfg})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if formatter == nil {
		t.Fatal("expected non-nil formatter")
	}
	var _ output.Formatter = formatter
}

// --- list command ---

func TestListCmd_InvalidRegex(t *testing.T) {
	_, err := execCmd("list", "--regex", "[invalid(")
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Errorf("error should mention 'invalid regex', got: %v", err)
	}
}

func TestListCmd_InvalidFormat(t *testing.T) {
	_, err := execCmd("list", "--regex", "/tmp/.*", "--format", "nope")
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should mention the bad format name, got: %v", err)
	}
}

func TestListCmd_OTLPFormat_MissingEndpoint(t *testing.T) {
	_, err := execCmd("list", "--regex", "/tmp/.*", "--format", "otlp")
	if err == nil {
		t.Fatal("expected error when --otlp-endpoint is missing, got nil")
	}
	if !strings.Contains(err.Error(), "otlp-endpoint") {
		t.Errorf("error should mention otlp-endpoint, got: %v", err)
	}
}

func TestListCmd_ValidScan_TableOutput(t *testing.T) {
	stdout, err := execCmd("list", "--regex", "/dev/null")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "UID") || !strings.Contains(stdout, "PATH") {
		t.Errorf("expected table header in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "/dev/null") {
		t.Errorf("expected /dev/null in output, got:\n%s", stdout)
	}
}

func TestListCmd_ValidScan_JSONOutput(t *testing.T) {
	stdout, err := execCmd("list", "--regex", "/dev/null", "--format", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout), "[") {
		t.Errorf("expected JSON array output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "/dev/null") {
		t.Errorf("expected /dev/null in JSON output, got:\n%s", stdout)
	}
}

func TestListCmd_DefaultFormat_IsTable(t *testing.T) {
	stdout, err := execCmd("list", "--regex", "/dev/null")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "PATH") {
		t.Errorf("default format should be table, got:\n%s", stdout)
	}
}

func TestListCmd_DefaultRegex_IsMatchAll(t *testing.T) {
	cmd := newListCmd()
	flag := cmd.Flags().Lookup("regex")
	if flag == nil {
		t.Fatal("expected --regex flag to be registered")
	}
	if flag.DefValue != "/" {
		t.Errorf("expected default regex %q, got %q", "/", flag.DefValue)
	}
}

// --- watch command ---

// newFakeOTLPCollector starts a lightweight HTTP server that accepts any
// OTLP/HTTP log export request, returns 200 OK, and increments a counter
// for each request received. It lets tests exercise real export behavior
// for the otlp format (the only format watch supports) without depending
// on an actual collector.
func newFakeOTLPCollector(t *testing.T) (endpoint string, hits *int32) {
	t.Helper()
	hits = new(int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), hits
}

func TestWatchCmd_RequiresOTLPFormat(t *testing.T) {
	_, err := execCmd("watch", "--regex", "/tmp/.*", "--format", "table")
	if err == nil {
		t.Fatal("expected error when format is not otlp, got nil")
	}
	if !strings.Contains(err.Error(), "otlp") {
		t.Errorf("error should mention otlp, got: %v", err)
	}
}

func TestWatchCmd_InvalidRegex(t *testing.T) {
	_, err := execCmd("watch", "--format", "otlp", "--otlp-endpoint", "localhost:4317", "--regex", "[invalid(")
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Errorf("error should mention 'invalid regex', got: %v", err)
	}
}

func TestWatchCmd_NonOTLPFormatRejected(t *testing.T) {
	_, err := execCmd("watch", "--regex", "/tmp/.*", "--format", "nope")
	if err == nil {
		t.Fatal("expected error for non-otlp format, got nil")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should mention the bad format name, got: %v", err)
	}
}

func TestWatchCmd_StopsOnContextCancellation(t *testing.T) {
	endpoint, hits := newFakeOTLPCollector(t)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_, err := execCmdCtx(ctx, "watch", "--regex", "/dev/null", "--interval", "20ms",
		"--format", "otlp", "--otlp-protocol", "http", "--otlp-endpoint", endpoint)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(hits) == 0 {
		t.Error("expected at least one export to reach the fake OTLP collector")
	}
}

func TestWatchCmd_DedupesRepeatedMatches(t *testing.T) {
	endpoint, hits := newFakeOTLPCollector(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err := execCmdCtx(ctx, "watch", "--regex", "/dev/null", "--interval", "10ms",
		"--format", "otlp", "--otlp-protocol", "http", "--otlp-endpoint", endpoint)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Many polls occur within the timeout window (10ms interval), but each
	// unique open file descriptor entry should only be exported once thanks
	// to the hash-based dedup cache, so the collector should see very few
	// requests despite the many scans performed.
	if got := atomic.LoadInt32(hits); got > 2 {
		t.Errorf("expected dedup to limit exports to at most 2 requests, got %d", got)
	}
}
