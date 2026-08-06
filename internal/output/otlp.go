package output

import (
	"errors"
	"io"

	"github.com/moonkev/pherret/internal/scan"
)

// OTLPFormatter renders matches as open telemetry log events.
type OTLPFormatter struct {
	w io.Writer
}

func (f *OTLPFormatter) Format(matches []scan.Match) error {
	return errors.New("OTLP formatter not yet supported")
}
