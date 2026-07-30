//go:build !linux && !darwin

package scan

import (
	"fmt"
	"regexp"
	"runtime"
)

type unsupportedScanner struct{}

func newScanner() Scanner {
	return &unsupportedScanner{}
}

func (s *unsupportedScanner) Scan(re *regexp.Regexp) ([]Match, int, error) {
	return nil, 0, fmt.Errorf("unsupported OS %q: no scan backend implemented yet", runtime.GOOS)
}
