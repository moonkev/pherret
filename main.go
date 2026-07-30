package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"text/tabwriter"

	"github.com/moonkev/pherret/internal/scan"
)

func main() {
	log.SetFlags(0) // no timestamp prefix on error messages
	log.SetPrefix("error: ")

	regexStr := flag.String("regex", "", "Regex used to match open file paths (required)")
	jsonOut := flag.Bool("json", false, "Emit JSON output")
	flag.Parse()

	if *regexStr == "" {
		log.Println("-regex is required")
		flag.Usage()
		os.Exit(2)
	}

	re, err := regexp.Compile(*regexStr)
	if err != nil {
		log.Fatalf("invalid regex: %v", err)
	}

	scanner := scan.NewScanner()
	matches, skipped, err := scanner.Scan(re)
	if err != nil {
		log.Fatal(err)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(matches); err != nil {
			log.Fatalf("failed to encode JSON: %v", err)
		}
	} else {
		if err := printTable(matches); err != nil {
			log.Fatalf("failed to write output: %v", err)
		}
	}

	if skipped > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "note: skipped %d process(es) due to permission or read errors\n", skipped)
	}
}

func printTable(matches []scan.Match) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "UID\tUSER\tPID\tFD\tCWD\tEXE\tOPEN_PATH"); err != nil {
		return err
	}
	for _, m := range matches {
		if _, err := fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%s\t%s\n", m.UID, m.User, m.PID, m.FD, m.CWD, m.Exe, m.OpenPath); err != nil {
			return err
		}
	}
	return w.Flush()
}
