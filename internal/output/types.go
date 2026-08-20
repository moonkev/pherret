package output

import (
	"fmt"
	"strings"
)

// Config holds all user-configurable settings for every output format.
// Only the fields relevant to the selected format are consulted; the rest
// are ignored. As new formats gain configuration options, add a nested
// struct here (following the OTLP pattern) rather than growing New's
// parameter list.
type Config struct {
	// OTLP holds settings used only when the "otlp" format is selected.
	// It is a pointer so that Config can be constructed before flag parsing
	// occurs (e.g. via cobra) and still reflect the values set by flags at
	// the time New is called.
	OTLP *OTLPConfig
	// CSV holds settings used only when the "csv" format is selected.
	// It is a pointer for the same reason as OTLP above.
	CSV *CsvConfig
}

// OTLPConfig holds all user-configurable settings for the OTLP log exporter.
type OTLPConfig struct {
	// Endpoint is the OTLP collector address, e.g. "localhost:4318" (http) or
	// "localhost:4317" (grpc). Do not include a scheme.
	Endpoint string
	// Protocol selects the transport: "http" or "grpc". Defaults to "grpc".
	Protocol string
	// URLPath overrides the request path when Protocol is "http".
	URLPath string
	// Headers are additional request headers/metadata sent with every export.
	Headers []string
	// TLS enables a TLS (or mTLS) connection to Endpoint. When false, the
	// connection is made in plaintext.
	TLS bool
	// InsecureSkipVerify disables server certificate verification when TLS is
	// enabled. Should only be used for testing.
	InsecureSkipVerify bool
	// CACertFile, if set, is a PEM encoded CA certificate bundle used to
	// verify the server's certificate instead of the system trust store.
	CACertFile string
	// ClientCertFile and ClientKeyFile, if both set, enable mutual TLS by
	// presenting a client certificate to the server.
	ClientCertFile string
	ClientKeyFile  string
}

type CsvConfig struct {
	// IncludeHeader determines whether to include a header row in the CSV output.
	IncludeHeader bool
	// OutputFilePath specifies the path to the output CSV file. If empty, output will be written to stdout.
	FilePath string
}

// Validate checks the configuration for internal consistency.
func (c OTLPConfig) Validate() error {
	if c.Endpoint == "" {
		return fmt.Errorf("otlp: --otlp-endpoint is required")
	}

	switch c.Protocol {
	case "", "http", "grpc":
	default:
		return fmt.Errorf("otlp: unsupported protocol %q: valid choices are: http, grpc", c.Protocol)
	}

	if (c.ClientCertFile == "") != (c.ClientKeyFile == "") {
		return fmt.Errorf("otlp: both client cert and client key must be set for mTLS")
	}

	if !c.TLS {
		if c.CACertFile != "" || c.ClientCertFile != "" || c.ClientKeyFile != "" {
			return fmt.Errorf("otlp: TLS must be enabled to use a CA cert or client certificate")
		}
	}

	return nil
}

// ParsedOTLPHeaders parses a list of "Key=Value" strings into a header map.
func (c OTLPConfig) ParsedOTLPHeaders() (map[string]string, error) {
	return ParseOTLPHeaders(c.Headers)
}

// ParseOTLPHeaders parses a list of "Key=Value" strings into a header map.
// Returns a nil map if headers is empty.
func ParseOTLPHeaders(headers []string) (map[string]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}

	parsed := make(map[string]string, len(headers))
	for _, pair := range headers {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid otlp header %q: expected format Key=Value", pair)
		}
		parsed[key] = value
	}
	return parsed, nil
}
