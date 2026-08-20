package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/moonkev/pherret/internal/output"
	"github.com/moonkev/pherret/internal/scan"
	"github.com/spf13/cobra"
)

// hashMatch computes a stable hash for a scan.Match so repeated occurrences
// across polling intervals can be detected and suppressed.
func hashMatch(m scan.Match) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d|%s|%d|%s|%s|%s|%s", m.UID, m.User, m.PID, m.CWD, m.Exe, m.FD, m.Path)
	return hex.EncodeToString(h.Sum(nil))
}

// addOTLPFlags registers the --otlp-* flags on cmd and returns the flag set
// backing them.
func addOTLPFlags(cmd *cobra.Command) *output.OTLPConfig {
	cfg := &output.OTLPConfig{}

	cmd.Flags().StringVar(&cfg.Endpoint, "otlp-endpoint", "",
		"OTLP collector endpoint host:port (required when --format=otlp)")
	cmd.Flags().StringVar(&cfg.Protocol, "otlp-protocol", "grpc",
		"OTLP transport protocol: grpc or http")
	cmd.Flags().StringVar(&cfg.URLPath, "otlp-url-path", "",
		"URL path for the OTLP http protocol, e.g. /v1/logs (http only)")
	cmd.Flags().StringArrayVar(&cfg.Headers, "otlp-header", nil,
		"Additional OTLP request header/metadata as Key=Value (repeatable)")
	cmd.Flags().BoolVar(&cfg.TLS, "otlp-tls", false,
		"Use TLS when connecting to the OTLP endpoint")
	cmd.Flags().BoolVar(&cfg.InsecureSkipVerify, "otlp-insecure-skip-verify", false,
		"Skip TLS certificate verification for the OTLP endpoint (insecure, requires --otlp-tls)")
	cmd.Flags().StringVar(&cfg.CACertFile, "otlp-ca-cert", "",
		"Path to a PEM encoded CA certificate used to verify the OTLP server (requires --otlp-tls)")
	cmd.Flags().StringVar(&cfg.ClientCertFile, "otlp-client-cert", "",
		"Path to a PEM encoded client certificate for mTLS (requires --otlp-tls and --otlp-client-key)")
	cmd.Flags().StringVar(&cfg.ClientKeyFile, "otlp-client-key", "",
		"Path to a PEM encoded client private key for mTLS (requires --otlp-tls and --otlp-client-cert)")

	return cfg
}

// addCsvFlags registers the --csv-* flags on cmd and returns the flag set backing them.
func addCsvFlags(cmd *cobra.Command) *output.CsvConfig {
	cfg := &output.CsvConfig{}

	cmd.Flags().StringVar(&cfg.FilePath, "csv-file", "",
		"Path to a CSV file to write output to (default: stdout)")
	cmd.Flags().BoolVar(&cfg.IncludeHeader, "csv-include-header", true,
		"Include a header row in the CSV output")

	return cfg
}

// addFlags registers all output-related flags on cmd and returns a Config.
func addFlags(cmd *cobra.Command) *output.Config {
	otlpFlags := addOTLPFlags(cmd)
	csvFlags := addCsvFlags(cmd)

	return &output.Config{
		OTLP: otlpFlags,
		CSV:  csvFlags,
	}
}

var rootCmd = &cobra.Command{
	Use:   "pherret",
	Short: "pherret lists open file descriptors across processes.",
}

func newListCmd() *cobra.Command {
	var regexStr string
	var format string
	var showSkipped bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List open file descriptors across processes and filter by file path regex.",
	}

	cfg := addFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		re, err := regexp.Compile(regexStr)
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}

		formatter, err := output.New(format, cfg)
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

		if showSkipped && skipped > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "note: skipped %d process(es) due to permission or read errors\n", skipped)
		}

		return nil
	}

	cmd.Flags().StringVarP(&regexStr, "regex", "r", "/", "Regex to filter open file paths (required)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json, otlp)")
	cmd.Flags().BoolVarP(&showSkipped, "show-skipped", "s", false,
		"Print message to stderr number showing skipped processes due to permission or read errors")

	return cmd
}

func newWatchCmd() *cobra.Command {
	var regexStr string
	var format string
	var interval time.Duration
	var showSkipped bool

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuously watch open file descriptors across processes and filter by file path regex.",
	}

	cfg := addFlags(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {

		if format != "otlp" {
			return fmt.Errorf("the only supported format for watch is otlp, got: %s", format)
		}

		re, err := regexp.Compile(regexStr)
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}

		formatter, err := output.New(format, cfg)
		if err != nil {
			return err
		}

		scanner := scan.NewScanner()

		// seen caches the hash of every match already output, so that
		// unchanged entries are not printed again on subsequent scans.
		seen := make(map[string]struct{})

		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			matches, skipped, err := scanner.Scan(re)
			if err != nil {
				return err
			}

			newMatches := make([]scan.Match, 0, len(matches))
			for _, m := range matches {
				h := hashMatch(m)
				if _, ok := seen[h]; ok {
					continue
				}
				seen[h] = struct{}{}
				newMatches = append(newMatches, m)
			}

			if len(newMatches) > 0 {
				if err := formatter.Format(newMatches); err != nil {
					return err
				}
			}

			if showSkipped && skipped > 0 {
				_, _ = fmt.Fprintf(os.Stderr, "note: skipped %d process(es) due to permission or read errors\n", skipped)
			}

			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	}

	cmd.Flags().StringVarP(&regexStr, "regex", "r", "/", "Regex to filter open file paths (required)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json, otlp)")
	cmd.Flags().DurationVarP(&interval, "interval", "i", 2*time.Second, "Polling interval between scans")
	cmd.Flags().BoolVarP(&showSkipped, "show-skipped", "s", false,
		"Print message to stderr number showing skipped processes due to permission or read errors")
	return cmd
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listCmd := newListCmd()
	watchCmd := newWatchCmd()
	rootCmd.AddCommand(listCmd, watchCmd)
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
