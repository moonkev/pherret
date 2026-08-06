package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/moonkev/pherret/internal/scan"
)

// fixtures shared across tests
var (
	emptyMatches = []scan.Match{}

	singleMatch = []scan.Match{
		{UID: 1000, User: "alice", PID: 42, FD: "3", CWD: "/home/alice", Exe: "/usr/bin/cat", OpenPath: "/tmp/foo.txt"},
	}

	multiMatches = []scan.Match{
		{UID: 1000, User: "alice", PID: 42, FD: "3", CWD: "/home/alice", Exe: "/usr/bin/cat", OpenPath: "/tmp/foo.txt"},
		{UID: 0, User: "root", PID: 1, FD: "10", CWD: "/", Exe: "/sbin/init", OpenPath: "/var/log/syslog"},
	}
)

// --- factory ---

func TestNew_ValidFormats(t *testing.T) {
	for _, name := range []string{"table", "json", "otlp"} {
		f, err := New(name)
		if err != nil {
			t.Errorf("New(%q) unexpected error: %v", name, err)
		}
		if f == nil {
			t.Errorf("New(%q) returned nil formatter", name)
		}
	}
}

func TestNew_UnknownFormat(t *testing.T) {
	_, err := New("csv")
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
	f, _ := NewWithWriter("table", &buf)
	if err := f.Format(emptyMatches); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	for _, col := range []string{"UID", "USER", "PID", "FD", "CWD", "EXE", "OPEN_PATH"} {
		if !strings.Contains(got, col) {
			t.Errorf("table header missing column %q; output:\n%s", col, got)
		}
	}
}

func TestTableFormatter_SingleMatch(t *testing.T) {
	var buf bytes.Buffer
	f, _ := NewWithWriter("table", &buf)
	if err := f.Format(singleMatch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	m := singleMatch[0]
	for _, want := range []string{m.User, m.CWD, m.Exe, m.OpenPath, m.FD} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q; output:\n%s", want, got)
		}
	}
}

func TestTableFormatter_MultipleMatches(t *testing.T) {
	var buf bytes.Buffer
	f, _ := NewWithWriter("table", &buf)
	if err := f.Format(multiMatches); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf.String()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	// header + one line per match
	if len(lines) != 1+len(multiMatches) {
		t.Errorf("expected %d lines (header + %d matches), got %d;\noutput:\n%s",
			1+len(multiMatches), len(multiMatches), len(lines), got)
	}
}

// --- JSONFormatter ---

func TestJSONFormatter_EmptyMatches(t *testing.T) {
	var buf bytes.Buffer
	f, _ := NewWithWriter("json", &buf)
	if err := f.Format(emptyMatches); err != nil {
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
	f, _ := NewWithWriter("json", &buf)
	if err := f.Format(singleMatch); err != nil {
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
		m.FD != want.FD || m.CWD != want.CWD || m.Exe != want.Exe || m.OpenPath != want.OpenPath {
		t.Errorf("match mismatch:\nwant %+v\ngot  %+v", want, m)
	}
}

func TestJSONFormatter_MultipleMatches(t *testing.T) {
	var buf bytes.Buffer
	f, _ := NewWithWriter("json", &buf)
	if err := f.Format(multiMatches); err != nil {
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
	f, _ := NewWithWriter("json", &buf)
	if err := f.Format(singleMatch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "\n  ") {
		t.Errorf("expected indented JSON output; got:\n%s", buf.String())
	}
}

// --- OTLPFormatter ---

func TestOTLPFormatter_ReturnsNotSupportedError(t *testing.T) {
	var buf bytes.Buffer
	f, _ := NewWithWriter("otlp", &buf)
	err := f.Format(singleMatch)
	if err == nil {
		t.Fatal("expected error from OTLP formatter, got nil")
	}
	if !errors.Is(err, err) || !strings.Contains(strings.ToLower(err.Error()), "not yet supported") {
		t.Errorf("unexpected error message: %v", err)
	}
}

