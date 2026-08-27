package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	port           int
	listenAddr     string
	target         string
	certificate    string
	privateKey     string
	configPath     string
	reloadInterval time.Duration
)

// defaultListenHost binds the loopback interface only. The proxy holds usable
// client certificates, so listening on every interface would offer them to
// anyone able to reach the machine. Binding elsewhere is opt-in via -listen.
const defaultListenHost = "127.0.0.1"

// logLevelFlag adapts logLevel to the flag package while remaining usable as a
// bare boolean flag, so that the original "-verbose" spelling keeps working
// alongside "-verbose=debug".
type logLevelFlag struct{}

func (logLevelFlag) String() string { return string(level) }

func (logLevelFlag) Set(value string) error {
	switch strings.ToLower(value) {
	case "none", "false", "off", "0":
		level = logLevelNone
	case "info", "true", "on", "1", "":
		level = logLevelInfo
	case "debug":
		level = logLevelDebug
	default:
		return fmt.Errorf("invalid log level %q: want none, info or debug", value)
	}
	return nil
}

// IsBoolFlag lets "-verbose" be given without a value, as it was before log
// levels existed. A level is supplied as "-verbose=debug".
func (logLevelFlag) IsBoolFlag() bool { return true }

// init binds flags for command line arguments
func init() {
	flag.IntVar(&port, "port", 8080, "port to listen on")
	flag.StringVar(&listenAddr, "listen", "", "address to listen on, e.g. 127.0.0.1:8080 (overrides -port)")
	flag.StringVar(&target, "target", "", "target host")
	flag.StringVar(&certificate, "certificate", "certificate.crt", "certificate file")
	flag.StringVar(&privateKey, "key", "private.key", "key file")
	flag.StringVar(&configPath, "config", "", "path to a YAML configuration file enabling multiple client certificates")
	flag.DurationVar(&reloadInterval, "reload-interval", defaultReloadInterval, "how often to check certificate files for changes")
	flag.Var(logLevelFlag{}, "verbose", "log level: none, info or debug (-verbose=debug)")
}

// main creates local http server, and forwards all requests to the target
// server that uses mTLS authentication. Which client certificate is presented
// is chosen per request when a configuration file defines several.
func main() {
	flag.Parse()
	applyLogLevel()

	handler, addr, err := setup(explicitFlags())
	if err != nil {
		fmt.Printf("%s\n\n", err)
		flag.Usage()
		os.Exit(1)
	}

	logInfo("🟢 Starting local forwarder on %s...", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: handler,
		// Bounded only for the request header, so that slow or streaming
		// bodies are not cut short.
		ReadHeaderTimeout: 20 * time.Second,
	}

	fmt.Printf("exit: %+v\n", server.ListenAndServe())
}

// explicitFlags reports which flags were actually supplied on the command
// line. Several flags have non-empty defaults, so the value alone cannot
// distinguish "not given" from "given the default".
func explicitFlags() map[string]bool {
	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// setup resolves configuration from the file and command line, and builds the
// handler and listen address.
func setup(set map[string]bool) (http.Handler, string, error) {
	cfg := &Config{}

	if configPath != "" {
		loaded, err := LoadConfig(configPath)
		if err != nil {
			return nil, "", err
		}
		cfg = loaded
	}

	// An explicitly supplied flag overrides the configuration file.
	if target != "" && (set["target"] || cfg.Target == "") {
		cfg.Target = target
	}

	if err := cfg.Validate(); err != nil {
		return nil, "", err
	}

	fallback, err := buildFallback(cfg, set)
	if err != nil {
		return nil, "", err
	}

	if len(cfg.Clients) == 0 && fallback == nil {
		return nil, "", fmt.Errorf("no client certificate configured: supply -certificate and -key, or list clients in -config")
	}

	// Clients that nothing can ever select would otherwise start cleanly and
	// reject every request.
	if len(cfg.Clients) > 0 && cfg.Selector.Header == "" && cfg.Selector.Default == "" && fallback == nil {
		return nil, "", fmt.Errorf("clients are configured but none can be selected: set selector.header to choose per request, or selector.default to choose one")
	}

	registry, err := NewRegistry(cfg, fallback, reloadInterval)
	if err != nil {
		return nil, "", err
	}

	if cfg.Selector.Header != "" {
		logInfo("🟢 Selecting client certificate from %s header (default: %s)",
			cfg.Selector.Header, describeDefault(cfg.Selector.Default, fallback))
	}

	return NewForwardHandler(registry, cfg.Selector), resolveListenAddr(cfg, set), nil
}

// buildFallback constructs the identity used when a request selects no client.
//
// Without a configuration file this is the only identity, which preserves the
// original single-certificate behaviour. With one, it is created only when the
// certificate flags were given explicitly, so that their defaults do not
// silently shadow the configured clients.
func buildFallback(cfg *Config, set map[string]bool) (*identity, error) {
	if configPath != "" && !set["certificate"] && !set["key"] {
		return nil, nil
	}

	if cfg.Target == "" {
		return nil, fmt.Errorf("target host is required")
	}

	return newIdentity("", cfg.Target, certificate, privateKey, reloadInterval)
}

// describeDefault renders the fallback used when the selector header is absent.
func describeDefault(configured string, fallback *identity) string {
	if configured != "" {
		return configured
	}
	if fallback != nil {
		return fallback.displayName()
	}
	return "none, header is required"
}

// resolveListenAddr determines the bind address, preferring explicit command
// line flags over the configuration file.
func resolveListenAddr(cfg *Config, set map[string]bool) string {
	if set["listen"] && listenAddr != "" {
		return listenAddr
	}
	if set["port"] {
		return fmt.Sprintf("%s:%d", defaultListenHost, port)
	}
	if cfg.Listen != "" {
		return cfg.Listen
	}
	return fmt.Sprintf("%s:%d", defaultListenHost, port)
}
