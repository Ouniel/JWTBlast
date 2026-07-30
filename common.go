package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds all configuration for the tool.
type Config struct {
	Token          string
	DictFile       string
	PubKeyFile     string
	PrivKeyFile    string
	Endpoint       string
	ModifiedClaims string
	ReportFile     string
	Workers        int
	Timeout        time.Duration
	Proxy          string
	TransportMode  string // json | bearer | cookie | url
	CookieName     string
	URLParam        string
	JWKSURL        string
	Samples        int
	Threshold      float64
	NestedDepth    int
	BombMode       bool
	Secret         string
	InjValue       string
	InjType        string
}

// VulnerabilityResult represents a single vulnerability finding.
type VulnerabilityResult struct {
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Payload     string            `json:"payload,omitempty"`
	Confirmed   bool              `json:"confirmed"`
	Details     map[string]string `json:"details,omitempty"`
}

// Report holds the complete scan report.
type Report struct {
	Target          string                `json:"target"`
	Timestamp       string                `json:"timestamp"`
	FoundSecret     string                `json:"found_secret"`
	Attempts        int64                 `json:"attempts"`
	Vulnerabilities []VulnerabilityResult `json:"vulnerabilities"`
	Recommendations []string              `json:"recommendations"`
	Logs            []string              `json:"logs"`
}

// HTTPClient creates an HTTP client with timeout, TLS skip, and proxy support.
func HTTPClient(cfg *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// sendToken sends a JWT token to the endpoint using the configured transport mode.
func sendToken(cfg *Config, token string) (*http.Response, error) {
	client := HTTPClient(cfg)

	switch cfg.TransportMode {
	case "bearer":
		req, err := http.NewRequest("GET", cfg.Endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return client.Do(req)

	case "cookie":
		name := cfg.CookieName
		if name == "" {
			name = "token"
		}
		req, err := http.NewRequest("GET", cfg.Endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Cookie", name+"="+token)
		return client.Do(req)

	case "url":
		param := cfg.URLParam
		if param == "" {
			param = "token"
		}
		sep := "?"
		if strings.Contains(cfg.Endpoint, "?") {
			sep = "&"
		}
		fullURL := cfg.Endpoint + sep + param + "=" + url.QueryEscape(token)
		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			return nil, err
		}
		return client.Do(req)

	default: // token — send raw JWT string as request body
		req, err := http.NewRequest("POST", cfg.Endpoint, strings.NewReader(token))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "text/plain")
		return client.Do(req)
	}
}

// sendTokenAndCheck sends a token and returns whether it was accepted (HTTP < 400).
func sendTokenAndCheck(cfg *Config, token string) (bool, int, string) {
	resp, err := sendToken(cfg, token)
	if err != nil {
		return false, 0, "error: " + err.Error()
	}
	defer resp.Body.Close()
	body := readBody(resp)
	accepted := resp.StatusCode >= 200 && resp.StatusCode < 400
	return accepted, resp.StatusCode, body
}

// readBody reads and returns the HTTP response body as string.
func readBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

// writeReport writes the report to a JSON file.
func writeReport(file string, report Report) {
	if report.Timestamp == "" {
		report.Timestamp = time.Now().Format("2006-01-02T15:04:05Z07:00")
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling report: %v\n", err)
		return
	}
	if err := os.WriteFile(file, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing report file: %v\n", err)
	}
}

// confirmOnline prompts the user for confirmation before online testing.
func confirmOnline(cfg *Config) bool {
	if cfg.Endpoint == "" {
		return false
	}
	fmt.Printf("Confirm online test against %s (y/n): ", cfg.Endpoint)
	var input string
	fmt.Scanln(&input)
	return strings.ToLower(strings.TrimSpace(input)) == "y"
}

// decodeTokenParts splits and decodes a JWT token into header, payload maps, and raw signature.
func decodeTokenParts(token string) (header, payload map[string]interface{}, sig string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", fmt.Errorf("invalid token: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to decode header: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse header JSON: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to decode payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse payload JSON: %w", err)
	}

	return header, payload, parts[2], nil
}

// encodeTokenPart base64url-encodes a JSON map.
func encodeTokenPart(m map[string]interface{}) (string, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// getPayloadBase64 returns the base64url-encoded payload as-is from the token.
func getPayloadBase64(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}
	return parts[1], nil
}

// signWithHMAC signs the signing input with the specified HMAC algorithm.
func signWithHMAC(signingInput string, key []byte, alg string) (string, error) {
	var sig []byte
	switch alg {
	case "HS256":
		h := hmac.New(sha256.New, key)
		h.Write([]byte(signingInput))
		sig = h.Sum(nil)
	case "HS384":
		h := hmac.New(sha512.New384, key)
		h.Write([]byte(signingInput))
		sig = h.Sum(nil)
	case "HS512":
		h := hmac.New(sha512.New, key)
		h.Write([]byte(signingInput))
		sig = h.Sum(nil)
	default:
		return "", fmt.Errorf("unsupported HMAC algorithm: %s", alg)
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// constructHmacJWT builds a complete JWT with HMAC signing.
func constructHmacJWT(header, payload map[string]interface{}, key []byte, alg string) (string, error) {
	headerEnc, err := encodeTokenPart(header)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}
	payloadEnc, err := encodeTokenPart(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}
	signingInput := headerEnc + "." + payloadEnc
	sigEnc, err := signWithHMAC(signingInput, key, alg)
	if err != nil {
		return "", err
	}
	return signingInput + "." + sigEnc, nil
}

// constructHmacJWTWithRawPayload builds a JWT with HMAC signing, preserving the
// original base64 payload encoding (useful for header-only modification attacks).
func constructHmacJWTWithRawPayload(header map[string]interface{}, payloadB64 string, key []byte, alg string) (string, error) {
	headerEnc, err := encodeTokenPart(header)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}
	signingInput := headerEnc + "." + payloadB64
	sigEnc, err := signWithHMAC(signingInput, key, alg)
	if err != nil {
		return "", err
	}
	return signingInput + "." + sigEnc, nil
}

// getAlg extracts the algorithm from a JWT token header.
func getAlg(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", err
	}
	return header.Alg, nil
}

// verifySignature verifies a JWT token's signature with the given secret and algorithm.
// FIX: Now uses WithValidMethods to prevent algorithm confusion during verification.
func verifySignature(tokenStr, secret, alg string) bool {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{alg}),
		jwt.WithoutClaimsValidation(),
	)
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != alg {
			return nil, fmt.Errorf("unexpected algorithm: %s, expected: %s", t.Method.Alg(), alg)
		}
		return []byte(secret), nil
	}
	_, err := parser.Parse(tokenStr, keyFunc)
	return err == nil
}

// newResult creates a VulnerabilityResult with the given fields.
func newResult(name, category, severity, description string) VulnerabilityResult {
	return VulnerabilityResult{
		Name:        name,
		Category:    category,
		Severity:    severity,
		Description: description,
	}
}

// addResult appends a VulnerabilityResult to the report.
func addResult(report *Report, result VulnerabilityResult) {
	report.Vulnerabilities = append(report.Vulnerabilities, result)
}

// readFile reads a file and returns its contents as a byte slice.
func readFile(file string) ([]byte, error) {
	return os.ReadFile(file)
}

// unmarshalJSON unmarshals JSON data into the target.
func unmarshalJSON(data []byte, target interface{}) error {
	return json.Unmarshal(data, target)
}
