//go:build darwin

package scan

import "testing"

func TestSanitizeDarwinPath(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  string
		valid bool
	}{
		{name: "normal path", in: "/dev/null", want: "/dev/null", valid: true},
		{name: "root path", in: "/", want: "/", valid: true},
		{name: "control byte", in: "/#\x01", valid: false},
		{name: "missing leading slash", in: "tmp/file", valid: false},
		{name: "single char root entry", in: "/G", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sanitizeDarwinPath(tt.in)
			if ok != tt.valid {
				t.Fatalf("valid = %v, want %v", ok, tt.valid)
			}
			if got != tt.want {
				t.Fatalf("path = %q, want %q", got, tt.want)
			}
		})
	}
}

