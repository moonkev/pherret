package main

import (
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/moonkev/pherret/internal/output"
	"github.com/moonkev/pherret/internal/scan"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pherret",
	Short: "pherret scans open file descriptors across processes.",
}

func newScanCmd() *cobra.Command {
	var regexStr string
	var format string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan open file descriptors across processes and filter by file path regex.",
		RunE: func(cmd *cobra.Command, args []string) error {
			re, err := regexp.Compile(regexStr)
			if err != nil {
				return fmt.Errorf("invalid regex: %w", err)
			}

			formatter, err := output.NewWithWriter(format, cmd.OutOrStdout())
			if err != nil {
				return err
			}

			scanner := scan.NewScanner()
			matches, skipped, err := scanner.Scan(re)
			if err != nil {
				return err
			}

			if err := formatter.Format(matches); err != nil {
				return err
			}

			if skipped > 0 {
				_, _ = fmt.Fprintf(os.Stderr, "note: skipped %d process(es) due to permission or read errors\n", skipped)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&regexStr, "regex", "r", "", "Regex to filter open file paths (required)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json, otlp)")
	_ = cmd.MarkFlagRequired("regex")

	return cmd
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("error: ")

	rootCmd.AddCommand(newScanCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
