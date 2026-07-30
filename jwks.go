package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// wellKnownPaths contains common JWKS discovery paths to probe.
var wellKnownPaths = []string{
	"/.well-known/jwks.json",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/oauth/jwks",
	"/oauth/jwks.json",
	"/auth/jwks",
	"/auth/jwks.json",
	"/jwks",
	"/jwks.json",
	"/keys",
	"/keys.json",
	"/certs",
	"/.well-known/jwt-jwks",
	"/api/jwks",
	"/api/keys",
	"/auth/realms/master/protocol/openid-connect/certs",
}

// JWKSDiscovery represents the result of JWKS endpoint discovery.
type JWKSDiscovery struct {
	URL        string                 `json:"url"`
	StatusCode int                    `json:"status_code"`
	Accessible bool                   `json:"accessible"`
	JWKS       map[string]interface{} `json:"jwks,omitempty"`
	KeyCount   int                    `json:"key_count"`
	Issues     []string               `json:"issues,omitempty"`
}

// discoverJWKS discovers and analyzes JWKS endpoints from a target domain.
func discoverJWKS(cfg *Config) {
	if cfg.Endpoint == "" {
		fmt.Println("[JWKS] This test requires an endpoint. Use --endpoint flag.")
		return
	}

	baseURL := extractBaseURL(cfg.Endpoint)
	if baseURL == "" {
		log.Fatal("Failed to extract base URL from endpoint")
	}

	fmt.Printf("[JWKS] Scanning %s for JWKS endpoints...\n", baseURL)

	report := Report{}
	client := HTTPClient(cfg)

	discoveries := []JWKSDiscovery{}
	foundEndpoints := 0

	for _, path := range wellKnownPaths {
		url := baseURL + path
		resp, err := client.Get(url)
		if err != nil {
			continue
		}

		body := readBody(resp)
		resp.Body.Close()

		discovery := JWKSDiscovery{
			URL:        url,
			StatusCode: resp.StatusCode,
			Accessible: resp.StatusCode >= 200 && resp.StatusCode < 300,
		}

		if discovery.Accessible {
			foundEndpoints++
			fmt.Printf("[JWKS] Found accessible endpoint: %s (HTTP %d)\n", url, resp.StatusCode)

			if strings.Contains(body, "\"keys\"") {
				var jwks map[string]interface{}
				if err := json.Unmarshal([]byte(body), &jwks); err == nil {
					discovery.JWKS = jwks
					if keys, ok := jwks["keys"].([]interface{}); ok {
						discovery.KeyCount = len(keys)
						fmt.Printf("[JWKS] Valid JWKS with %d keys\n", len(keys))

						for i, key := range keys {
							if keyMap, ok := key.(map[string]interface{}); ok {
								issues := analyzeJWKKey(keyMap, i)
								discovery.Issues = append(discovery.Issues, issues...)
							}
						}
					}
				}
			} else if strings.Contains(body, "\"jwks_uri\"") {
				var oidcConfig map[string]interface{}
				if err := json.Unmarshal([]byte(body), &oidcConfig); err == nil {
					if jwksURI, ok := oidcConfig["jwks_uri"].(string); ok {
						fmt.Printf("[JWKS] Found jwks_uri in OIDC config: %s\n", jwksURI)
						discovery.Issues = append(discovery.Issues, "OIDC config found with jwks_uri: "+jwksURI)

						jwksResp, err := client.Get(jwksURI)
						if err == nil {
							jwksBody := readBody(jwksResp)
							jwksResp.Body.Close()
							if jwksResp.StatusCode == 200 {
								var jwks map[string]interface{}
								if err := json.Unmarshal([]byte(jwksBody), &jwks); err == nil {
									discovery.JWKS = jwks
									if keys, ok := jwks["keys"].([]interface{}); ok {
										discovery.KeyCount = len(keys)
										for i, key := range keys {
											if keyMap, ok := key.(map[string]interface{}); ok {
												issues := analyzeJWKKey(keyMap, i)
												discovery.Issues = append(discovery.Issues, issues...)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		discoveries = append(discoveries, discovery)
	}

	if foundEndpoints > 0 {
		addResult(&report, VulnerabilityResult{
			Name:        "Exposed JWKS Endpoint",
			Category:    "JWKS Discovery",
			Severity:    "MEDIUM",
			Description: fmt.Sprintf("Found %d accessible JWKS-related endpoints. Exposed key material can aid attackers in crafting algorithm confusion attacks.", foundEndpoints),
			Confirmed:   true,
			Details: map[string]string{
				"endpoints_found": fmt.Sprintf("%d", foundEndpoints),
				"base_url":        baseURL,
			},
		})
	} else {
		addResult(&report, newResult(
			"JWKS Discovery (not found)",
			"JWKS Discovery",
			"INFO",
			"No accessible JWKS endpoints were found on the target domain",
		))
	}

	for _, d := range discoveries {
		if len(d.Issues) > 0 {
			addResult(&report, VulnerabilityResult{
				Name:        fmt.Sprintf("JWKS Key Issues: %s", d.URL),
				Category:    "JWKS Discovery",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("JWKS endpoint at %s has key issues: %s", d.URL, strings.Join(d.Issues, "; ")),
				Confirmed:   true,
				Details: map[string]string{
					"url":    d.URL,
					"issues": strings.Join(d.Issues, "; "),
				},
			})
		}
	}

	for _, d := range discoveries {
		if d.Accessible {
			fmt.Printf("  [%d] %s - %d keys, %d issues\n",
				d.StatusCode, d.URL, d.KeyCount, len(d.Issues))
		}
	}

	report.Recommendations = append(report.Recommendations,
		"Restrict JWKS endpoint access to internal services only (network-level ACL)",
		"Use short-lived keys and rotate frequently (e.g., every 90 days)",
		"Ensure all keys use minimum 2048-bit RSA or 256-bit ECDSA",
		"Do not expose private key material in JWKS endpoints",
		"Monitor JWKS endpoint access for anomalous requests",
		"Use HTTPS with certificate pinning for all JWKS fetch operations",
	)
	writeReport(cfg.ReportFile, report)
}

// analyzeJWKKey analyzes a single JWK for security issues.
func analyzeJWKKey(key map[string]interface{}, index int) []string {
	var issues []string

	kty, _ := key["kty"].(string)
	alg, _ := key["alg"].(string)

	// Check RSA key size via the 'n' parameter length
	if kty == "RSA" {
		if n, ok := key["n"].(string); ok {
			nBytes, err := base64.RawURLEncoding.DecodeString(n)
			if err == nil {
				keyBits := len(nBytes) * 8
				if keyBits < 2048 {
					issues = append(issues, fmt.Sprintf("Key #%d: RSA key size %d bits is below 2048-bit minimum", index, keyBits))
				}
				if keyBits < 1024 {
					issues = append(issues, fmt.Sprintf("Key #%d: RSA key size %d bits is critically weak", index, keyBits))
				}
			}
		}
	}

	// Check algorithm
	switch alg {
	case "none":
		issues = append(issues, fmt.Sprintf("Key #%d: Algorithm 'none' is present in JWKS", index))
	case "HS256", "HS384", "HS512":
		issues = append(issues, fmt.Sprintf("Key #%d: HMAC algorithm %s in JWKS (should not be public)", index, alg))
	case "RS1":
		issues = append(issues, fmt.Sprintf("Key #%d: Weak algorithm %s (SHA-1 based)", index, alg))
	}

	// Check for exposed private key material
	privateParams := []string{"d", "p", "q", "dp", "dq", "qi"}
	for _, param := range privateParams {
		if _, ok := key[param]; ok {
			issues = append(issues, fmt.Sprintf("Key #%d: Private key material (%s) exposed in JWKS!", index, param))
		}
	}

	// Check use field
	if use, ok := key["use"].(string); ok && use != "sig" && use != "enc" {
		issues = append(issues, fmt.Sprintf("Key #%d: Unusual key use: %s", index, use))
	}

	return issues
}

// extractBaseURL extracts the base URL (scheme://host[:port]) from a full URL.
func extractBaseURL(fullURL string) string {
	schemeEnd := strings.Index(fullURL, "://")
	if schemeEnd < 0 {
		return ""
	}
	hostStart := schemeEnd + 3
	hostEnd := strings.Index(fullURL[hostStart:], "/")
	if hostEnd < 0 {
		return fullURL
	}
	return fullURL[:hostStart+hostEnd]
}
