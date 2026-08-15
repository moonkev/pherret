package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moonkev/pherret/internal/scan"
)

// fixtures shared across tests
var (
	emptyMatches = []scan.Match{}

	singleMatch = []scan.Match{
		{UID: 1000, User: "alice", PID: 42, FD: "3", CWD: "/home/alice", Exe: "/usr/bin/cat", Path: "/tmp/foo.txt"},
	}

	multiMatches = []scan.Match{
		{UID: 1000, User: "alice", PID: 42, FD: "3", CWD: "/home/alice", Exe: "/usr/bin/cat", Path: "/tmp/foo.txt"},
		{UID: 0, User: "root", PID: 1, FD: "10", CWD: "/", Exe: "/sbin/init", Path: "/var/log/syslog"},
	}
)

// --- factory ---

func TestNew_ValidFormats(t *testing.T) {
	for _, name := range []string{"table", "json", "otlp"} {
		f, err := New(name, Config{})
		if err != nil {
			t.Errorf("New(%q) unexpected error: %v", name, err)
		}
		if f == nil {
			t.Errorf("New(%q) returned nil formatter", name)
		}
	}
}

func TestNew_UnknownFormat(t *testing.T) {
	_, err := New("csv", Config{})
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "csv") {
		t.Errorf("error message should mention the bad format name, got: %v", err)
	}
}

// --- TableFormatter ---

func TestTableFormatter_Header(t *testing.T) {
	var buf bytes.Buffer
	f := &TableFormatter{w: &buf}
	if err := f.Format(emptyMatches, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	for _, col := range []string{"UID", "USER", "PID", "FD", "CWD", "EXE", "PATH"} {
		if !strings.Contains(got, col) {
			t.Errorf("table header missing column %q; output:\n%s", col, got)
		}
	}
}

func TestTableFormatter_HeaderOmittedWhenNotFirstScan(t *testing.T) {
	var buf bytes.Buffer
	f := &TableFormatter{w: &buf}
	if err := f.Format(singleMatch, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	if strings.Contains(got, "UID") {
		t.Errorf("expected no header when firstScan is false; output:\n%s", got)
	}
	if !strings.Contains(got, singleMatch[0].Path) {
		t.Errorf("expected match data in output; output:\n%s", got)
	}
}

func TestTableFormatter_SingleMatch(t *testing.T) {
	var buf bytes.Buffer
	f := &TableFormatter{w: &buf}
	if err := f.Format(singleMatch, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	m := singleMatch[0]
	for _, want := range []string{m.User, m.CWD, m.Exe, m.Path, m.FD} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q; output:\n%s", want, got)
		}
	}
}

func TestTableFormatter_MultipleMatches(t *testing.T) {
	var buf bytes.Buffer
	f := &TableFormatter{w: &buf}
	if err := f.Format(multiMatches, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 1+len(multiMatches) {
		t.Errorf("expected %d lines (header + %d matches), got %d;\noutput:\n%s",
			1+len(multiMatches), len(multiMatches), len(lines), got)
	}
}

// --- JSONFormatter ---

func TestJSONFormatter_EmptyMatches(t *testing.T) {
	var buf bytes.Buffer
	f := &JSONFormatter{w: &buf}
	if err := f.Format(emptyMatches, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []scan.Match
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if len(got) != 0 {
		t.Errorf("expected empty array, got %d elements", len(got))
	}
}

func TestJSONFormatter_SingleMatch(t *testing.T) {
	var buf bytes.Buffer
	f := &JSONFormatter{w: &buf}
	if err := f.Format(singleMatch, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []scan.Match
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
	m := got[0]
	want := singleMatch[0]
	if m.UID != want.UID || m.User != want.User || m.PID != want.PID ||
		m.FD != want.FD || m.CWD != want.CWD || m.Exe != want.Exe || m.Path != want.Path {
		t.Errorf("match mismatch:\nwant %+v\ngot  %+v", want, m)
	}
}

func TestJSONFormatter_MultipleMatches(t *testing.T) {
	var buf bytes.Buffer
	f := &JSONFormatter{w: &buf}
	if err := f.Format(multiMatches, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []scan.Match
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if len(got) != len(multiMatches) {
		t.Errorf("expected %d matches, got %d", len(multiMatches), len(got))
	}
}

func TestJSONFormatter_IsIndented(t *testing.T) {
	var buf bytes.Buffer
	f := &JSONFormatter{w: &buf}
	if err := f.Format(singleMatch, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "\n  ") {
		t.Errorf("expected indented JSON output; got:\n%s", buf.String())
	}
}

func TestJSONFormatter_FirstScanDoesNotAffectOutput(t *testing.T) {
	var bufFirst, bufLater bytes.Buffer
	fFirst := &JSONFormatter{w: &bufFirst}
	fLater := &JSONFormatter{w: &bufLater}

	if err := fFirst.Format(singleMatch, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := fLater.Format(singleMatch, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bufFirst.String() != bufLater.String() {
		t.Errorf("expected JSON output to be identical regardless of firstScan; first:\n%s\nlater:\n%s",
			bufFirst.String(), bufLater.String())
	}
}

// --- OTLPFormatter ---

func TestOTLPFormatter_MissingEndpoint(t *testing.T) {
	f := &OTLPFormatter{}
	err := f.Format(singleMatch, true)
	if err == nil {
		t.Fatal("expected error from OTLP formatter with no endpoint configured, got nil")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestOTLPConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     OTLPConfig
		wantErr bool
	}{
		{"missing endpoint", OTLPConfig{}, true},
		{"valid http", OTLPConfig{Endpoint: "localhost:4318", Protocol: "http"}, false},
		{"valid grpc", OTLPConfig{Endpoint: "localhost:4317", Protocol: "grpc"}, false},
		{"default protocol", OTLPConfig{Endpoint: "localhost:4318"}, false},
		{"bad protocol", OTLPConfig{Endpoint: "localhost:4318", Protocol: "carrier-pigeon"}, true},
		{"client cert without key", OTLPConfig{Endpoint: "localhost:4318", TLS: true, ClientCertFile: "cert.pem"}, true},
		{"client key without cert", OTLPConfig{Endpoint: "localhost:4318", TLS: true, ClientKeyFile: "key.pem"}, true},
		{"ca cert without tls", OTLPConfig{Endpoint: "localhost:4318", CACertFile: "ca.pem"}, true},
		{"mtls without tls", OTLPConfig{Endpoint: "localhost:4318", ClientCertFile: "cert.pem", ClientKeyFile: "key.pem"}, true},
		{"valid mtls", OTLPConfig{Endpoint: "localhost:4318", TLS: true, ClientCertFile: "cert.pem", ClientKeyFile: "key.pem"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseOTLPHeaders(t *testing.T) {
	got, err := ParseOTLPHeaders([]string{"Authorization=Bearer abc", "stream-name=test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]string{"Authorization": "Bearer abc", "stream-name": "test"}
	if len(got) != len(want) {
		t.Fatalf("expected %d headers, got %d", len(want), len(got))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("header %q: want %q, got %q", k, v, got[k])
		}
	}
}

func TestParseOTLPHeaders_Invalid(t *testing.T) {
	_, err := ParseOTLPHeaders([]string{"no-equals-sign"})
	if err == nil {
		t.Fatal("expected error for malformed header, got nil")
	}
}

func TestParseOTLPHeaders_Empty(t *testing.T) {
	got, err := ParseOTLPHeaders(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil map for no headers, got %v", got)
	}
}
