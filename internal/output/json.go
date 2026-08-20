package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/moonkev/pherret/internal/scan"
)

// JSONFormatter renders matches as indented JSON.
type JSONFormatter struct {
	// w is the destination to write JSON to. If nil, os.Stdout is used.
	w io.Writer
}

func (f *JSONFormatter) Format(matches []scan.Match) error {
	w := f.w
	if w == nil {
		w = os.Stdout
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(matches); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}
