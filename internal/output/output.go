package output

import (
	"fmt"

	"github.com/moonkev/pherret/internal/scan"
)

// Formatter writes a slice of matches to some output destination.
type Formatter interface {
	Format(matches []scan.Match) error
}

// New returns the Formatter for the given format name.
// Stream-based formatters write to os.Stdout. cfg carries format-specific
// settings (e.g. cfg.OTLP); fields for formats other than the one selected
// are ignored.
// Returns an error listing valid choices if the name is unknown.
func New(format string, cfg *Config) (Formatter, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	switch format {
	case "table":
		return &TableFormatter{}, nil
	case "csv":
		csvCfg := cfg.CSV
		if csvCfg == nil {
			csvCfg = &CsvConfig{}
		}
		return &CsvFormatter{cfg: *csvCfg}, nil
	case "json":
		return &JSONFormatter{}, nil
	case "otlp":
		otlpCfg := cfg.OTLP
		if otlpCfg == nil {
			otlpCfg = &OTLPConfig{}
		}
		if err := otlpCfg.Validate(); err != nil {
			return nil, err
		}
		return &OTLPFormatter{cfg: *otlpCfg}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q: valid choices are: table, csv, json, otlp", format)
	}
}
