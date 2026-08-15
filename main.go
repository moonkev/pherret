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

// otlpFlagSet holds the raw CLI flag values used to configure the OTLP
// output formatter.
type otlpFlagSet struct {
	endpoint           string
	protocol           string
	urlPath            string
	headers            []string
	tls                bool
	insecureSkipVerify bool
	caCert             string
	clientCert         string
	clientKey          string
}

// addOTLPFlags registers the --otlp-* flags on cmd and returns the flag set
// backing them.
func addOTLPFlags(cmd *cobra.Command) *otlpFlagSet {
	f := &otlpFlagSet{}

	cmd.Flags().StringVar(&f.endpoint, "otlp-endpoint", "",
		"OTLP collector endpoint host:port (required when --format=otlp)")
	cmd.Flags().StringVar(&f.protocol, "otlp-protocol", "grpc",
		"OTLP transport protocol: grpc or http")
	cmd.Flags().StringVar(&f.urlPath, "otlp-url-path", "",
		"URL path for the OTLP http protocol, e.g. /v1/logs (http only)")
	cmd.Flags().StringArrayVar(&f.headers, "otlp-header", nil,
		"Additional OTLP request header/metadata as Key=Value (repeatable)")
	cmd.Flags().BoolVar(&f.tls, "otlp-tls", false,
		"Use TLS when connecting to the OTLP endpoint")
	cmd.Flags().BoolVar(&f.insecureSkipVerify, "otlp-insecure-skip-verify", false,
		"Skip TLS certificate verification for the OTLP endpoint (insecure, requires --otlp-tls)")
	cmd.Flags().StringVar(&f.caCert, "otlp-ca-cert", "",
		"Path to a PEM encoded CA certificate used to verify the OTLP server (requires --otlp-tls)")
	cmd.Flags().StringVar(&f.clientCert, "otlp-client-cert", "",
		"Path to a PEM encoded client certificate for mTLS (requires --otlp-tls and --otlp-client-key)")
	cmd.Flags().StringVar(&f.clientKey, "otlp-client-key", "",
		"Path to a PEM encoded client private key for mTLS (requires --otlp-tls and --otlp-client-cert)")

	return f
}

// toConfig converts the raw flag values into an output.Config, parsing
// headers along the way.
func (f *otlpFlagSet) toConfig() (output.Config, error) {
	headers, err := output.ParseOTLPHeaders(f.headers)
	if err != nil {
		return output.Config{}, err
	}

	return output.Config{
		OTLP: output.OTLPConfig{
			Endpoint:           f.endpoint,
			Protocol:           f.protocol,
			URLPath:            f.urlPath,
			Headers:            headers,
			TLS:                f.tls,
			InsecureSkipVerify: f.insecureSkipVerify,
			CACertFile:         f.caCert,
			ClientCertFile:     f.clientCert,
			ClientKeyFile:      f.clientKey,
		},
	}, nil
}

// newFormatter builds the output.Formatter for format, resolving and
// validating configuration from otlpFlags when needed.
func newFormatter(format string, otlpFlags *otlpFlagSet) (output.Formatter, error) {
	cfg, err := otlpFlags.toConfig()
	if err != nil {
		return nil, err
	}

	if format == "otlp" && cfg.OTLP.Endpoint == "" {
		return nil, fmt.Errorf("--otlp-endpoint is required when --format=otlp")
	}

	return output.New(format, cfg)
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

	otlpFlags := addOTLPFlags(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		re, err := regexp.Compile(regexStr)
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}

		formatter, err := newFormatter(format, otlpFlags)
		if err != nil {
			return err
		}

		scanner := scan.NewScanner()
		matches, skipped, err := scanner.Scan(re)
		if err != nil {
			return err
		}

		if err := formatter.Format(matches, true); err != nil {
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

	firstScan := true

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuously watch open file descriptors across processes and filter by file path regex.",
	}

	otlpFlags := addOTLPFlags(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		re, err := regexp.Compile(regexStr)
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}

		formatter, err := newFormatter(format, otlpFlags)
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
				if err := formatter.Format(newMatches, firstScan); err != nil {
					return err
				}
				if firstScan {
					firstScan = false
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
