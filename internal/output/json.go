package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/moonkev/pherret/internal/scan"
)

// JSONFormatter renders matches as indented JSON.
type JSONFormatter struct {
	w io.Writer
}

func (f *JSONFormatter) Format(matches []scan.Match, firstScan bool) error {
	enc := json.NewEncoder(f.w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(matches); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}
