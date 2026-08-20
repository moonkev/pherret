package output

import (
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/moonkev/pherret/internal/scan"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
)

// TableFormatter renders matches as a human-readable aligned table.
type TableFormatter struct {
	// w is the destination to write the table to. If nil, os.Stdout is used.
	w io.Writer
}

func (f *TableFormatter) Format(matches []scan.Match) (err error) {
	w := f.w
	if w == nil {
		w = os.Stdout
	}

	colorCfg := renderer.ColorizedConfig{
		Header: renderer.Tint{
			FG: renderer.Colors{color.FgGreen, color.Bold},
		},
	}
	table := tablewriter.NewTable(w, tablewriter.WithRenderer(renderer.NewColorized(colorCfg)))
	defer func(table *tablewriter.Table) {
		err = table.Close()
	}(table)

	table.Header("UID", "USER", "PID", "FD", "CWD", "EXE", "PATH")
	tableData := make([][]any, len(matches))
	for i, m := range matches {
		tableData[i] = []any{m.UID, m.User, m.PID, m.FD, m.CWD, m.Exe, m.Path}
	}
	if err = table.Bulk(tableData); err != nil {
		return err
	}
	return table.Render()
}
