package output

import (
	"fmt"
	"os"

	"github.com/moonkev/pherret/internal/scan"
)

// Formatter writes a slice of matches to some output destination.
type Formatter interface {
	Format(matches []scan.Match, firstScan bool) error
}

// New returns the Formatter for the given format name.
// Stream-based formatters write to os.Stdout. cfg carries format-specific
// settings (e.g. cfg.OTLP); fields for formats other than the one selected
// are ignored.
// Returns an error listing valid choices if the name is unknown.
func New(format string, cfg Config) (Formatter, error) {
	switch format {
	case "table":
		return &TableFormatter{w: os.Stdout}, nil
	case "json":
		return &JSONFormatter{w: os.Stdout}, nil
	case "otlp":
		return &OTLPFormatter{cfg: cfg.OTLP}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q: valid choices are: table, json, otlp", format)
	}
}
