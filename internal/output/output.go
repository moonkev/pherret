package output

import (
	"fmt"
	"io"
	"os"

	"github.com/moonkev/pherret/internal/scan"
)

// Formatter writes a slice of matches to some output destination.
type Formatter interface {
	Format(matches []scan.Match) error
}

// New returns the Formatter for the given format name, writing to os.Stdout.
// Returns an error listing valid choices if the name is unknown.
func New(format string) (Formatter, error) {
	return NewWithWriter(format, os.Stdout)
}

// NewWithWriter returns the Formatter for the given format name, writing to w.
// This is primarily useful for testing.
func NewWithWriter(format string, w io.Writer) (Formatter, error) {
	switch format {
	case "table":
		return &TableFormatter{w: w}, nil
	case "json":
		return &JSONFormatter{w: w}, nil
	case "otlp":
		return &OTLPFormatter{w: w}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q: valid choices are: table, json, otlp", format)
	}
}
