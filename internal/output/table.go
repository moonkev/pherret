package output

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/moonkev/pherret/internal/scan"
)

// TableFormatter renders matches as a human-readable aligned table.
type TableFormatter struct {
	w io.Writer
}

func (f *TableFormatter) Format(matches []scan.Match) error {
	w := tabwriter.NewWriter(f.w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "UID\tUSER\tPID\tFD\tCWD\tEXE\tOPEN_PATH"); err != nil {
		return err
	}
	for _, m := range matches {
		if _, err := fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%s\t%s\n",
			m.UID, m.User, m.PID, m.FD, m.CWD, m.Exe, m.OpenPath); err != nil {
			return err
		}
	}
	return w.Flush()
}
