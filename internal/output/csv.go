package output

import (
	"encoding/csv"
	"io"
	"os"
	"strconv"

	"github.com/moonkev/pherret/internal/scan"
)

// CsvFormatter renders matches as a CSV.
type CsvFormatter struct {
	cfg CsvConfig
}

func (f *CsvFormatter) Format(matches []scan.Match) (err error) {

	var writer io.Writer
	if f.cfg.FilePath != "" {
		var fileFlags int
		fileFlags = os.O_RDWR | os.O_CREATE | os.O_TRUNC
		file, err := os.OpenFile(f.cfg.FilePath, fileFlags, 0644)
		if err != nil {
			return err
		}
		defer func(file *os.File) {
			err = file.Close()
		}(file)
		writer = file
	} else {
		writer = os.Stdout
	}

	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()
	if f.cfg.IncludeHeader {
		if err = csvWriter.Write([]string{"UID", "USER", "PID", "FD", "CWD", "EXE", "PATH"}); err != nil {
			return err
		}
	}

	tableData := make([][]string, len(matches))
	for i, m := range matches {
		tableData[i] = []string{
			strconv.FormatInt(int64(m.UID), 10),
			m.User,
			strconv.FormatInt(int64(m.PID), 10),
			m.FD,
			m.CWD,
			m.Exe,
			m.Path,
		}
	}

	return csvWriter.WriteAll(tableData)
}
