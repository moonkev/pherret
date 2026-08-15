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
	OTLP OTLPConfig
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
	Headers map[string]string
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

// Validate checks the configuration for internal consistency.
func (c OTLPConfig) Validate() error {
	if c.Endpoint == "" {
		return fmt.Errorf("otlp: endpoint is required")
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

// ParseOTLPHeaders parses a list of "Key=Value" strings into a header map.
func ParseOTLPHeaders(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}

	headers := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid otlp header %q: expected format Key=Value", pair)
		}
		headers[key] = value
	}
	return headers, nil
}
