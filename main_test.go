//go:build linux

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newTestRoot builds a fresh root+scan command tree for each test,
// avoiding shared state from the package-level rootCmd.
func newTestRoot() *cobra.Command {
	root := &cobra.Command{Use: "pherret"}
	root.AddCommand(newScanCmd())
	return root
}

func execCmd(args ...string) (stdout, stderr string, err error) {
	var outBuf, errBuf bytes.Buffer
	root := newTestRoot()
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestScanCmd_MissingRegex(t *testing.T) {
	_, _, err := execCmd("scan")
	if err == nil {
		t.Fatal("expected error when --regex is omitted, got nil")
	}
}

func TestScanCmd_InvalidRegex(t *testing.T) {
	_, _, err := execCmd("scan", "--regex", "[invalid(")
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Errorf("error should mention 'invalid regex', got: %v", err)
	}
}

func TestScanCmd_InvalidFormat(t *testing.T) {
	_, _, err := execCmd("scan", "--regex", "/tmp/.*", "--format", "nope")
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should mention the bad format name, got: %v", err)
	}
}

func TestScanCmd_ValidScan_TableOutput(t *testing.T) {
	// /dev/null is always open in every process, so this will always produce results.
	stdout, _, err := execCmd("scan", "--regex", "/dev/null")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "UID") || !strings.Contains(stdout, "OPEN_PATH") {
		t.Errorf("expected table header in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "/dev/null") {
		t.Errorf("expected /dev/null in output, got:\n%s", stdout)
	}
}

func TestScanCmd_ValidScan_JSONOutput(t *testing.T) {
	stdout, _, err := execCmd("scan", "--regex", "/dev/null", "--format", "json")
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

func TestScanCmd_DefaultFormat_IsTable(t *testing.T) {
	// Omitting --format should produce table output (header row present).
	stdout, _, err := execCmd("scan", "--regex", "/dev/null")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "OPEN_PATH") {
		t.Errorf("default format should be table, got:\n%s", stdout)
	}
}
