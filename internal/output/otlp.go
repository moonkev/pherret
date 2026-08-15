package output

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/moonkev/pherret/internal/scan"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc/credentials"
)

// OTLPFormatter renders matches as open telemetry log events.
type OTLPFormatter struct {
	cfg OTLPConfig
}

// buildTLSConfig constructs a *tls.Config from the CA/client cert settings in cfg.
func buildTLSConfig(cfg OTLPConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file %q: %w", cfg.CACertFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert file %q as PEM", cfg.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert/key pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

func newHTTPExporter(ctx context.Context, cfg OTLPConfig) (sdklog.Exporter, error) {
	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(cfg.Endpoint),
	}

	if cfg.URLPath != "" {
		opts = append(opts, otlploghttp.WithURLPath(cfg.URLPath))
	}

	if len(cfg.Headers) > 0 {
		opts = append(opts, otlploghttp.WithHeaders(cfg.Headers))
	}

	if cfg.TLS {
		tlsCfg, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploghttp.WithTLSClientConfig(tlsCfg))
	} else {
		opts = append(opts, otlploghttp.WithInsecure())
	}

	return otlploghttp.New(ctx, opts...)
}

func newGRPCExporter(ctx context.Context, cfg OTLPConfig) (sdklog.Exporter, error) {
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(cfg.Endpoint),
	}

	if len(cfg.Headers) > 0 {
		opts = append(opts, otlploggrpc.WithHeaders(cfg.Headers))
	}

	if cfg.TLS {
		tlsCfg, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, otlploggrpc.WithInsecure())
	}

	return otlploggrpc.New(ctx, opts...)
}

func newExporter(ctx context.Context, cfg OTLPConfig) (sdklog.Exporter, error) {
	switch cfg.Protocol {
	case "grpc":
		return newGRPCExporter(ctx, cfg)
	case "", "http":
		return newHTTPExporter(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported otlp protocol %q: valid choices are: http, grpc", cfg.Protocol)
	}
}

func initLogger(ctx context.Context, cfg OTLPConfig) (*sdklog.LoggerProvider, error) {
	exporter, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Define resource attributes
	res, err := resource.New(ctx)
	if err != nil {
		return nil, err
	}

	// Create LoggerProvider using the aliased package
	processor := sdklog.NewBatchProcessor(exporter)
	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(processor),
	)

	return provider, nil
}

func (f *OTLPFormatter) Format(matches []scan.Match, firstScan bool) (err error) {
	if err := f.cfg.Validate(); err != nil {
		return err
	}

	ctx := context.Background()

	provider, err := initLogger(ctx, f.cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize otel logger: %w", err)
	}

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := provider.Shutdown(shutdownCtx); shutdownErr != nil && err == nil {
			err = fmt.Errorf("error shutting down log provider: %w", shutdownErr)
		}
	}()

	logger := otelslog.NewLogger("pherret", otelslog.WithLoggerProvider(provider))

	for _, match := range matches {
		logger.Info("Open file descriptor match",
			"uid", match.UID,
			"user", match.User,
			"pid", match.PID,
			"fd", match.FD,
			"cwd", match.CWD,
			"exe", match.Exe,
			"path", match.Path,
		)
	}

	return nil
}
