package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// sensitiveDataPatterns defines regex patterns for common sensitive data types
// that should never appear in JWT claims.
var sensitiveDataPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
	Severity string
}{
	{"Credit Card Number", regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`), "HIGH"},
	{"SSN (US)", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "HIGH"},
	{"Email Address", regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`), "MEDIUM"},
	{"Phone Number", regexp.MustCompile(`\b\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b`), "MEDIUM"},
	{"API Key (generic)", regexp.MustCompile(`\b(sk|pk|api_key|apikey|secret)[_-]?[A-Za-z0-9]{20,}\b`), "HIGH"},
	{"AWS Access Key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "HIGH"},
	{"AWS Secret Key", regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`), "MEDIUM"},
	{"Private Key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), "CRITICAL"},
	{"Password Field", regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|pass)\b`), "HIGH"},
	{"Bank Account", regexp.MustCompile(`\b\d{8,17}\b`), "MEDIUM"},
	{"IP Address", regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), "LOW"},
}

// requiredClaims lists JWT claims that should be present for security.
var requiredClaims = []struct {
	Claim    string
	Reason   string
	Severity string
}{
	{"iss", "Issuer claim identifies the token issuer; missing issuer allows token replay across services", "MEDIUM"},
	{"exp", "Expiration claim limits token lifetime; missing exp means tokens never expire", "HIGH"},
	{"sub", "Subject claim identifies the user; missing sub makes audit trails unreliable", "LOW"},
	{"iat", "Issued-at claim helps detect stale or replayed tokens", "LOW"},
}

// weakAlgorithms lists algorithms considered weak or insecure.
var weakAlgorithms = map[string]string{
	"none": "Algorithm 'none' disables signature verification entirely",
	"HS1":  "HMAC-SHA1 is cryptographically weak",
	"RS1":  "RSA-SHA1 is cryptographically weak",
	"ES1":  "ECDSA-SHA1 is cryptographically weak",
}

// auditToken performs a comprehensive security audit of a JWT token.
// This is a static analysis that examines the token's structure, claims,
// and metadata for security issues without requiring an online endpoint.
func auditToken(cfg *Config) {
	header, payload, sig, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	report := Report{}
	report.Target = "token-audit"

	fmt.Println("[Audit] Starting JWT security audit...")
	fmt.Println("=========================================")

	// 1. Algorithm audit
	auditAlgorithm(&report, header)

	// 2. Header parameter audit
	auditHeader(&report, header)

	// 3. Required claims audit
	auditRequiredClaims(&report, payload)

	// 4. Sensitive data audit
	auditSensitiveData(&report, payload)

	// 5. Expiration and lifetime audit
	auditExpiration(&report, payload)

	// 6. Audience and issuer audit
	auditAudienceIssuer(&report, payload)

	// 7. Signature strength audit
	auditSignature(&report, sig)

	// 8. Token size audit
	auditTokenSize(&report, cfg.Token)

	// Summary
	fmt.Println("=========================================")
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	for _, v := range report.Vulnerabilities {
		switch v.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	fmt.Printf("Audit complete: %d findings\n", len(report.Vulnerabilities))
	fmt.Printf("  CRITICAL: %d\n  HIGH: %d\n  MEDIUM: %d\n  LOW: %d\n",
		criticalCount, highCount, mediumCount, lowCount)

	report.Recommendations = append(report.Recommendations,
		"Follow RFC 7519 best practices for JWT claim structure",
		"Never store sensitive data (PII, credentials, financial info) in JWT claims",
		"Use short-lived access tokens (TTL < 15 minutes) with refresh token rotation",
		"Always include iss, exp, sub, and aud claims",
		"Use RS256 or ES256 instead of HS256 for distributed systems",
		"Never use 'none' algorithm in production",
		"Keep token size under 8KB to avoid HTTP header size issues",
	)
	writeReport(cfg.ReportFile, report)
}

// auditAlgorithm checks the JWT algorithm for security issues.
func auditAlgorithm(report *Report, header map[string]interface{}) {
	alg, _ := header["alg"].(string)
	fmt.Printf("\n[Algorithm] Algorithm: %s\n", alg)

	if alg == "" {
		addResult(report, newResult("Missing Algorithm", "Algorithm Audit", "CRITICAL",
			"No 'alg' field in JWT header. Some parsers may default to 'none' or skip verification."))
		return
	}

	if alg == "none" {
		addResult(report, newResult("'none' Algorithm", "Algorithm Audit", "CRITICAL",
			"Token uses 'none' algorithm which disables signature verification entirely. "+
				"Any party can forge tokens."))
	}

	if reason, ok := weakAlgorithms[alg]; ok {
		addResult(report, newResult(
			fmt.Sprintf("Weak Algorithm: %s", alg),
			"Algorithm Audit", "HIGH",
			fmt.Sprintf("%s. Use RS256, RS384, RS512, ES256, ES384, or ES512 instead.", reason),
		))
	}

	if strings.HasPrefix(alg, "HS") {
		addResult(report, newResult(
			fmt.Sprintf("HMAC Algorithm: %s", alg),
			"Algorithm Audit", "MEDIUM",
			"HMAC algorithms require shared secrets. In multi-service environments, "+
				"this means every service that verifies tokens has the ability to sign them. "+
				"Consider using asymmetric algorithms (RS256, ES256).",
		))
	}
}

// auditHeader checks JWT header parameters for security issues.
func auditHeader(report *Report, header map[string]interface{}) {
	fmt.Println("\n[Header] Checking header parameters...")

	// Check for dangerous header parameters
	dangerousParams := []string{"jwk", "jku", "x5c", "x5u", "x5t"}
	for _, param := range dangerousParams {
		if _, ok := header[param]; ok {
			addResult(report, newResult(
				fmt.Sprintf("Header Parameter: %s", param),
				"Header Audit", "HIGH",
				fmt.Sprintf("Token contains '%s' header parameter. This parameter can be used "+
					"for key injection attacks. Ensure the server ignores embedded keys and uses "+
					"only pre-registered keys via 'kid'.", param),
			))
		}
	}

	// Check for missing typ
	if typ, ok := header["typ"].(string); !ok || typ != "JWT" {
		addResult(report, newResult(
			"Missing 'typ' Header",
			"Header Audit", "LOW",
			"Token header does not specify typ='JWT'. This may cause confusion with other token types."),
		)
	}

	// Check for kid presence
	if _, ok := header["kid"]; !ok {
		addResult(report, newResult(
			"Missing 'kid' Header",
			"Header Audit", "LOW",
			"No 'kid' (Key ID) header. Key rotation and multi-key support require kid for proper key selection."),
		)
	}

	// Check for crit header
	if crit, ok := header["crit"]; ok {
		addResult(report, newResult(
			"'crit' Header Present",
			"Header Audit", "MEDIUM",
			fmt.Sprintf("Token contains 'crit' header with value: %v. "+
				"Ensure the server validates all critical parameters per RFC 7515 Section 4.1.11.", crit),
		))
	}
}

// auditRequiredClaims checks for the presence of required JWT claims.
func auditRequiredClaims(report *Report, payload map[string]interface{}) {
	fmt.Println("\n[Claims] Checking required claims...")

	for _, rc := range requiredClaims {
		if _, ok := payload[rc.Claim]; !ok {
			addResult(report, newResult(
				fmt.Sprintf("Missing Claim: %s", rc.Claim),
				"Claims Audit", rc.Severity,
				rc.Reason,
			))
			fmt.Printf("  [MISSING] %s\n", rc.Claim)
		} else {
			fmt.Printf("  [OK] %s\n", rc.Claim)
		}
	}
}

// auditSensitiveData scans JWT claims for sensitive data patterns.
func auditSensitiveData(report *Report, payload map[string]interface{}) {
	fmt.Println("\n[Sensitive Data] Scanning claims for sensitive information...")

	for key, value := range payload {
		strValue := fmt.Sprintf("%v", value)

		for _, pattern := range sensitiveDataPatterns {
			if pattern.Pattern.MatchString(strValue) {
				matches := pattern.Pattern.FindAllString(strValue, -1)
				matchDisplay := strings.Join(matches, ", ")
				if len(matchDisplay) > 100 {
					matchDisplay = matchDisplay[:100] + "..."
				}

				addResult(report, VulnerabilityResult{
					Name:        fmt.Sprintf("Sensitive Data in Claim: %s (%s)", key, pattern.Name),
					Category:    "Sensitive Data Audit",
					Severity:    pattern.Severity,
					Description: fmt.Sprintf("Claim '%s' contains what appears to be %s: %s. "+
						"Sensitive data should never be stored in JWT claims as they are "+
						"base64-encoded (not encrypted) and visible to any party with the token.",
						key, pattern.Name, matchDisplay),
					Confirmed: true,
					Details: map[string]string{
						"claim":      key,
						"data_type":  pattern.Name,
						"match":      matchDisplay,
					},
				})
				fmt.Printf("  [ALERT] %s: %s in claim '%s'\n", pattern.Name, matchDisplay, key)
			}
		}

		// Check claim name itself for sensitive patterns
		lowerKey := strings.ToLower(key)
		sensitiveKeywords := []string{"password", "passwd", "pwd", "secret", "token", "key", "credential", "credit", "ssn", "auth"}
		for _, kw := range sensitiveKeywords {
			if strings.Contains(lowerKey, kw) {
				addResult(report, newResult(
					fmt.Sprintf("Sensitive Claim Name: %s", key),
					"Sensitive Data Audit", "MEDIUM",
					fmt.Sprintf("Claim name '%s' contains sensitive keyword '%s'. "+
						"This claim may contain sensitive data that should not be in a JWT.", key, kw),
				))
				fmt.Printf("  [ALERT] Sensitive claim name: '%s'\n", key)
				break
			}
		}
	}
}

// auditExpiration checks token expiration and lifetime.
func auditExpiration(report *Report, payload map[string]interface{}) {
	fmt.Println("\n[Expiration] Checking token lifetime...")

	now := time.Now()

	// Check exp
	if expRaw, ok := payload["exp"]; ok {
		switch exp := expRaw.(type) {
		case float64:
			expTime := time.Unix(int64(exp), 0)
			lifetime := expTime.Sub(now)

			if lifetime < 0 {
				addResult(report, newResult(
					"Expired Token",
					"Expiration Audit", "HIGH",
					fmt.Sprintf("Token expired at %s (expired %s ago). "+
						"Expired tokens should be rejected by the server.", expTime.Format(time.RFC3339), -lifetime.Round(time.Second))),
				)
				fmt.Printf("  [EXPIRED] Token expired at %s\n", expTime.Format(time.RFC3339))
			} else {
				fmt.Printf("  [OK] Expires at %s (lifetime: %s)\n", expTime.Format(time.RFC3339), lifetime.Round(time.Second))

				// Check for excessive lifetime
				if lifetime > 24*time.Hour {
					addResult(report, newResult(
						"Excessive Token Lifetime",
						"Expiration Audit", "MEDIUM",
						fmt.Sprintf("Token lifetime is %s (expires at %s). "+
							"Access tokens should have short lifetimes (<15 minutes). "+
							"Long-lived tokens increase the window for token theft and replay.", lifetime.Round(time.Hour), expTime.Format(time.RFC3339))),
					)
					fmt.Printf("  [WARNING] Long lifetime: %s\n", lifetime.Round(time.Hour))
				}

				if lifetime > 7*24*time.Hour {
					addResult(report, newResult(
						"Critical: Extremely Long Token Lifetime",
						"Expiration Audit", "HIGH",
						fmt.Sprintf("Token lifetime is %s (>7 days). "+
							"This is excessive for access tokens and significantly increases security risk.", lifetime.Round(time.Hour))),
					)
				}
			}

			// Check iat vs exp for total token validity
			if iatRaw, ok := payload["iat"]; ok {
				if iat, ok := iatRaw.(float64); ok {
					iatTime := time.Unix(int64(iat), 0)
					totalValidity := expTime.Sub(iatTime)
					if totalValidity > 24*time.Hour {
						fmt.Printf("  [INFO] Total validity period: %s\n", totalValidity.Round(time.Hour))
					}
				}
			}
		}
	} else {
		addResult(report, newResult(
			"Missing Expiration",
			"Expiration Audit", "HIGH",
			"Token has no 'exp' claim. Without expiration, tokens are valid indefinitely, "+
				"creating a permanent security risk if stolen."),
		)
		fmt.Println("  [MISSING] No 'exp' claim - token never expires!")
	}

	// Check nbf
	if nbfRaw, ok := payload["nbf"]; ok {
		if nbf, ok := nbfRaw.(float64); ok {
			nbfTime := time.Unix(int64(nbf), 0)
			if nbfTime.After(now) {
				fmt.Printf("  [INFO] Token not yet valid (nbf: %s)\n", nbfTime.Format(time.RFC3339))
			}
		}
	}
}

// auditAudienceIssuer checks audience and issuer claims.
func auditAudienceIssuer(report *Report, payload map[string]interface{}) {
	fmt.Println("\n[Audience/Issuer] Checking issuer and audience...")

	if iss, ok := payload["iss"]; ok {
		issStr := fmt.Sprintf("%v", iss)
		fmt.Printf("  [OK] Issuer: %s\n", issStr)

		// Check for HTTP (non-HTTPS) issuer
		if strings.HasPrefix(issStr, "http://") {
			addResult(report, newResult(
				"HTTP Issuer URL",
				"Audience/Issuer Audit", "MEDIUM",
				fmt.Sprintf("Issuer URL uses HTTP instead of HTTPS: %s. "+
					"HTTP URLs are vulnerable to man-in-the-middle attacks.", issStr)),
			)
		}
	}

	if aud, ok := payload["aud"]; ok {
		switch v := aud.(type) {
		case string:
			fmt.Printf("  [OK] Audience: %s\n", v)
		case []interface{}:
			fmt.Printf("  [OK] Audiences: %d\n", len(v))
		}
	} else {
		addResult(report, newResult(
			"Missing Audience",
			"Audience/Issuer Audit", "MEDIUM",
			"Token has no 'aud' (audience) claim. Without audience validation, "+
				"a token issued for one service can be used against another service."),
		)
		fmt.Println("  [MISSING] No 'aud' claim - token can be replayed across services")
	}
}

// auditSignature checks signature strength.
func auditSignature(report *Report, sig string) {
	fmt.Println("\n[Signature] Analyzing signature...")

	if sig == "" {
		addResult(report, newResult(
			"Empty Signature",
			"Signature Audit", "CRITICAL",
			"Token has an empty signature. This indicates the 'none' algorithm is in use, "+
				"meaning the token is not signed at all."),
		)
		return
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		// Try with padding
		sigBytes, err = base64.URLEncoding.DecodeString(sig)
		if err != nil {
			addResult(report, newResult(
				"Invalid Signature Encoding",
				"Signature Audit", "MEDIUM",
				"Signature is not valid base64url-encoded. This may indicate a malformed token.",
			))
			return
		}
	}

	sigBits := len(sigBytes) * 8
	fmt.Printf("  Signature length: %d bytes (%d bits)\n", len(sigBytes), sigBits)

	if sigBits < 256 {
		addResult(report, newResult(
			"Short Signature",
			"Signature Audit", "MEDIUM",
			fmt.Sprintf("Signature is only %d bits. Modern signatures should be at least 256 bits.", sigBits)),
		)
	}
}

// auditTokenSize checks the overall token size.
func auditTokenSize(report *Report, token string) {
	fmt.Println("\n[Token Size] Checking token dimensions...")

	tokenBytes := len(token)
	tokenParts := strings.Split(token, ".")

	fmt.Printf("  Total size: %d bytes\n", tokenBytes)
	fmt.Printf("  Parts: %d\n", len(tokenParts))

	if len(tokenParts) != 3 {
		addResult(report, newResult(
			"Malformed Token Structure",
			"Token Size Audit", "HIGH",
			fmt.Sprintf("Token has %d parts instead of the expected 3 (header.payload.signature).", len(tokenParts))),
		)
		return
	}

	headerSize := len(tokenParts[0])
	payloadSize := len(tokenParts[1])
	sigSize := len(tokenParts[2])

	fmt.Printf("  Header: %d bytes, Payload: %d bytes, Signature: %d bytes\n",
		headerSize, payloadSize, sigSize)

	if tokenBytes > 8192 {
		addResult(report, newResult(
			"Oversized Token",
			"Token Size Audit", "MEDIUM",
			fmt.Sprintf("Token is %d bytes. Tokens over 8KB may cause HTTP header size issues "+
				"and should be reviewed for unnecessary data.", tokenBytes)),
		)
	}

	if payloadSize > 4096 {
		addResult(report, newResult(
			"Large Payload",
			"Token Size Audit", "LOW",
			fmt.Sprintf("Payload is %d bytes. Large payloads may contain unnecessary data "+
				"and increase token transmission overhead.", payloadSize)),
		)
	}
}
