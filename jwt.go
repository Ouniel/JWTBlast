package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "brute":
		cmdBrute()
	case "none":
		cmdNone()
	case "confusion":
		cmdConfusion()
	case "inject":
		cmdInject()
	case "tamper":
		cmdTamper()
	case "timing":
		cmdTiming()
	case "nested":
		cmdNested()
	case "jwks":
		cmdJWKS()
	case "audit":
		cmdAudit()
	case "scan":
		cmdScan()
	case "version":
		fmt.Println("JWTBlast v2.0 - JWT Security Testing Tool")
		fmt.Println("Supported: 10 attack modules, 40+ vulnerability types")
	case "help", "-h", "--help":
		usage()
	default:
		// If args[1] looks like a JWT (starts with ey... and has dots),
		// treat it as "audit <token>" shorthand.
		if isLikelyJWT(cmd) {
			os.Args = append([]string{os.Args[0], "audit"}, os.Args[1:]...)
			cmdAudit()
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

// isLikelyJWT checks if a string looks like a JWT token.
func isLikelyJWT(s string) bool {
	return strings.Count(s, ".") == 2 && len(s) > 20
}

// extractPositionalToken separates the first positional argument (JWT token)
// from the remaining flags. Returns (token, remainingArgs).
func extractPositionalToken(args []string) (string, []string) {
	var positional []string
	var flags []string

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
		} else if len(positional) == 0 {
			positional = append(positional, arg)
		} else {
			flags = append(flags, arg)
		}
	}

	if len(positional) > 0 {
		return positional[0], flags
	}
	return "", flags
}

// parseCommonFlags sets up flags common to all commands.
// Token is passed as the first positional argument, not a flag.
func parseCommonFlags(fs *flag.FlagSet) (*string, *string, *string, *time.Duration, *string, *string) {
	endpoint := fs.String("endpoint", "", "Target endpoint URL for online testing")
	report := fs.String("report", "report.json", "Report output file")
	transport := fs.String("transport", "token", "Token transport: token|bearer|cookie|url")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP request timeout")
	proxy := fs.String("proxy", "", "HTTP proxy URL (e.g., http://127.0.0.1:8080)")
	cookieName := fs.String("cookie-name", "token", "Cookie name (for -transport cookie)")
	return endpoint, report, transport, timeout, proxy, cookieName
}

// applyCommonConfig sets common config fields from parsed flags.
func applyCommonConfig(cfg *Config, transport, proxy string, timeout time.Duration, cookieName, urlParam *string) {
	cfg.TransportMode = transport
	cfg.Proxy = proxy
	cfg.Timeout = timeout
	if cookieName != nil {
		cfg.CookieName = *cookieName
	}
	if urlParam != nil {
		cfg.URLParam = *urlParam
	}
}

// parseArgsWithToken extracts the positional token and parses remaining flags.
func parseArgsWithToken(fs *flag.FlagSet) (token string) {
	args := os.Args[2:]
	token, remaining := extractPositionalToken(args)
	fs.Parse(remaining)
	return token
}

func cmdBrute() {
	fs := flag.NewFlagSet("brute", flag.ExitOnError)
	endpoint, report, transport, timeout, proxy, cookieName := parseCommonFlags(fs)
	dict := fs.String("dict", "", "Dictionary file for brute-force (required)")
	workers := fs.Int("workers", runtime.NumCPU(), "Number of worker goroutines")
	token := parseArgsWithToken(fs)

	if token == "" || *dict == "" {
		fmt.Fprintln(os.Stderr, "Usage: jwtblast brute <JWT> --dict wordlist.txt [--workers N]")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: token, DictFile: *dict, Endpoint: *endpoint,
		ReportFile: *report, Workers: *workers,
	}
	applyCommonConfig(cfg, *transport, *proxy, *timeout, cookieName, nil)
	bruteForce(cfg)
}

func cmdNone() {
	fs := flag.NewFlagSet("none", flag.ExitOnError)
	endpoint, report, transport, timeout, proxy, cookieName := parseCommonFlags(fs)
	modified := fs.String("modified-claims", "", "JSON string of modified claims to inject")
	token := parseArgsWithToken(fs)

	if token == "" {
		fmt.Fprintln(os.Stderr, "Usage: jwtblast none <JWT> [--endpoint URL]")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: token, Endpoint: *endpoint,
		ModifiedClaims: *modified, ReportFile: *report,
	}
	applyCommonConfig(cfg, *transport, *proxy, *timeout, cookieName, nil)
	testNoneAlg(cfg)
}

func cmdConfusion() {
	fs := flag.NewFlagSet("confusion", flag.ExitOnError)
	endpoint, report, transport, timeout, proxy, cookieName := parseCommonFlags(fs)
	pubkey := fs.String("pubkey", "", "RSA public key file (PEM) (required)")
	modified := fs.String("modified-claims", "", "JSON string of modified claims")
	token := parseArgsWithToken(fs)

	if token == "" || *pubkey == "" {
		fmt.Fprintln(os.Stderr, "Usage: jwtblast confusion <JWT> --pubkey public.pem [--endpoint URL]")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: token, PubKeyFile: *pubkey, Endpoint: *endpoint,
		ModifiedClaims: *modified, ReportFile: *report,
	}
	applyCommonConfig(cfg, *transport, *proxy, *timeout, cookieName, nil)
	testAlgConfusion(cfg)
}

func cmdInject() {
	fs := flag.NewFlagSet("inject", flag.ExitOnError)
	endpoint, report, transport, timeout, proxy, cookieName := parseCommonFlags(fs)
	injType := fs.String("type", "all", "Injection type: jwk|jku|x5c|x5u|kid|kid-traversal|kid-sql|kid-cmd|crit|all")
	injValue := fs.String("value", "", "Injection value (e.g., URL for jku/x5u, path for kid)")
	token := parseArgsWithToken(fs)

	if token == "" {
		fmt.Fprintln(os.Stderr, "Usage: jwtblast inject <JWT> --type jwk [--endpoint URL]")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: token, Endpoint: *endpoint,
		ReportFile: *report, InjType: *injType, InjValue: *injValue,
	}
	applyCommonConfig(cfg, *transport, *proxy, *timeout, cookieName, nil)
	testHeaderInjection(cfg)
}

func cmdTamper() {
	fs := flag.NewFlagSet("tamper", flag.ExitOnError)
	endpoint, report, transport, timeout, proxy, cookieName := parseCommonFlags(fs)
	secret := fs.String("secret", "", "Known HMAC secret for re-signing (if cracked)")
	privkey := fs.String("privkey", "", "RSA private key file for RS256 tampering")
	token := parseArgsWithToken(fs)

	if token == "" {
		fmt.Fprintln(os.Stderr, "Usage: jwtblast tamper <JWT> --secret mysecret [--endpoint URL]")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: token, Endpoint: *endpoint,
		ReportFile: *report, Secret: *secret, PrivKeyFile: *privkey,
	}
	applyCommonConfig(cfg, *transport, *proxy, *timeout, cookieName, nil)
	testClaimTamper(cfg)
}

func cmdTiming() {
	fs := flag.NewFlagSet("timing", flag.ExitOnError)
	endpoint, report, transport, timeout, proxy, cookieName := parseCommonFlags(fs)
	samples := fs.Int("samples", 50, "Number of samples per measurement")
	threshold := fs.Float64("threshold", 0.05, "Timing difference threshold (fraction)")
	token := parseArgsWithToken(fs)

	if token == "" {
		fmt.Fprintln(os.Stderr, "Usage: jwtblast timing <JWT> --endpoint URL [--samples N]")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: token, Endpoint: *endpoint,
		ReportFile: *report, Samples: *samples, Threshold: *threshold,
	}
	applyCommonConfig(cfg, *transport, *proxy, *timeout, cookieName, nil)
	testTimingAttack(cfg)
}

func cmdNested() {
	fs := flag.NewFlagSet("nested", flag.ExitOnError)
	endpoint, report, transport, timeout, proxy, cookieName := parseCommonFlags(fs)
	depth := fs.Int("depth", 10, "Nesting depth for JWT bomb")
	bomb := fs.Bool("bomb", false, "Generate JWT bomb only")
	token := parseArgsWithToken(fs)

	if token == "" {
		fmt.Fprintln(os.Stderr, "Usage: jwtblast nested <JWT> [--depth N] [--endpoint URL]")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: token, Endpoint: *endpoint,
		ReportFile: *report, NestedDepth: *depth, BombMode: *bomb,
	}
	applyCommonConfig(cfg, *transport, *proxy, *timeout, cookieName, nil)
	testNestedJWT(cfg)
}

func cmdJWKS() {
	fs := flag.NewFlagSet("jwks", flag.ExitOnError)
	endpoint, report, transport, timeout, proxy, cookieName := parseCommonFlags(fs)

	// JWKS uses endpoint as positional or flag
	args := os.Args[2:]
	var posToken string
	var remaining []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			remaining = append(remaining, arg)
		} else if posToken == "" {
			posToken = arg
		} else {
			remaining = append(remaining, arg)
		}
	}
	fs.Parse(remaining)

	if *endpoint == "" {
		fmt.Fprintln(os.Stderr, "Error: --endpoint is required for JWKS discovery")
		fmt.Fprintln(os.Stderr, "Usage: jwtblast jwks --endpoint URL")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: posToken, Endpoint: *endpoint,
		ReportFile: *report,
	}
	applyCommonConfig(cfg, *transport, *proxy, *timeout, cookieName, nil)
	discoverJWKS(cfg)
}

func cmdAudit() {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	report := fs.String("report", "audit_report.json", "Audit report file")
	token := parseArgsWithToken(fs)

	if token == "" {
		fmt.Fprintln(os.Stderr, "Usage: jwtblast audit <JWT> [--report file.json]")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: token, ReportFile: *report,
	}
	auditToken(cfg)
}

func cmdScan() {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	endpoint, report, transport, timeout, proxy, cookieName := parseCommonFlags(fs)
	dict := fs.String("dict", "", "Dictionary file for brute-force")
	pubkey := fs.String("pubkey", "", "Public key file (PEM)")
	privkey := fs.String("privkey", "", "Private key file (PEM)")
	secret := fs.String("secret", "", "Known HMAC secret")
	depth := fs.Int("depth", 10, "JWT bomb nesting depth")
	urlParam := fs.String("url-param", "token", "URL parameter name (for -transport url)")
	token := parseArgsWithToken(fs)

	if token == "" {
		fmt.Fprintln(os.Stderr, "Usage: jwtblast scan <JWT> [--dict wordlist.txt] [--endpoint URL]")
		fs.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Token: token, DictFile: *dict, PubKeyFile: *pubkey, PrivKeyFile: *privkey,
		Endpoint: *endpoint, ReportFile: *report, Secret: *secret,
		NestedDepth: *depth,
	}
	applyCommonConfig(cfg, *transport, *proxy, *timeout, cookieName, urlParam)
	fullScan(cfg)
}

func usage() {
	fmt.Print(`
JWTBlast v2.0 - JWT Security Testing Tool
=========================================

USAGE:
  jwtblast <command> <JWT> [flags]

  # Shorthand: omit "audit" to audit a token directly
  jwtblast <JWT>

COMMANDS:
  brute       HMAC secret brute-force attack
  none        alg=none signature bypass test
  confusion   RS256->HS256 algorithm confusion attack
  inject      Header injection attacks (JWK/JKU/x5c/x5u/KID/crit)
  tamper      Claim tampering and re-signing
  timing      Timing side-channel attack detection
  nested      Nested JWT and JWT bomb generation
  jwks        JWKS endpoint discovery and analysis
  audit       Static token security audit
  scan        Full comprehensive security scan (all tests)
  version     Show version info

EXAMPLES:
  # Static audit (no endpoint needed)
  jwtblast audit eyJhbGciOi...

  # Shorthand (omit "audit")
  jwtblast eyJhbGciOi...

  # Brute-force HMAC secret
  jwtblast brute eyJhbGciOi... --dict wordlist.txt --workers 16

  # Test alg=none bypass
  jwtblast none eyJhbGciOi... --endpoint https://target.com/api

  # Algorithm confusion (RS256->HS256)
  jwtblast confusion eyJhbGciOi... --pubkey public.pem --endpoint https://target.com/api

  # JWK header injection
  jwtblast inject eyJhbGciOi... --type jwk --endpoint https://target.com/api

  # KID path traversal
  jwtblast inject eyJhbGciOi... --type kid-traversal --endpoint https://target.com/api

  # Claim tampering with known secret
  jwtblast tamper eyJhbGciOi... --secret mysecret --endpoint https://target.com/api

  # Timing attack detection
  jwtblast timing eyJhbGciOi... --endpoint https://target.com/api --samples 100

  # JWT bomb generation
  jwtblast nested eyJhbGciOi... --depth 20 --endpoint https://target.com/api

  # JWKS endpoint discovery
  jwtblast jwks --endpoint https://target.com

  # Full scan
  jwtblast scan eyJhbGciOi... --dict wordlist.txt --pubkey public.pem --endpoint https://target.com/api

TRANSPORT MODES:
  -transport token    Send raw JWT string as POST body (default)
  -transport bearer   Send as Authorization: Bearer <JWT>
  -transport cookie   Send as Cookie: <name>=<JWT>
  -transport url      Send as ?<param>=<JWT>

SUPPORTED VULNERABILITIES (40+ types):
  Algorithm:     alg=none bypass, RS256->HS256 confusion, weak algorithms
  Header Inject: JWK, JKU, x5c, x5u, KID traversal, KID SQLi, KID cmd, crit bypass
  Token-level:   HMAC brute-force, claim tampering, timing oracle
  Structural:    Nested JWT, JWT bomb, self-referencing JWT
  Discovery:     JWKS enumeration, OIDC config, key analysis
  Audit:         Sensitive data, missing claims, oversized tokens, weak signatures
`)
}
