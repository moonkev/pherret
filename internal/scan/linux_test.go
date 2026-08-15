//go:build linux

package scan

import "testing"

func TestParseUIDFromStatus(t *testing.T) {
	input := []byte("Name:\tbash\nUid:\t1000\t1000\t1000\t1000\n")
	uid, err := parseUIDFromStatus(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != 1000 {
		t.Fatalf("expected uid 1000, got %d", uid)
	}
}
