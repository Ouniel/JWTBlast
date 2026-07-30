package main

import (
	"fmt"
	"time"
)

// fullScan runs all applicable tests against the target token.
// Tests that require specific inputs (e.g., pubkey for confusion) are
// skipped if the required input is not provided.
func fullScan(cfg *Config) {
	fmt.Println("========================================")
	fmt.Println("  JWTBlast Full Security Scan")
	fmt.Println("========================================")
	fmt.Printf("Target: %s\n", cfg.Endpoint)
	fmt.Printf("Time:   %s\n", time.Now().Format(time.RFC3339))
	fmt.Println("========================================")

	combinedReport := Report{
		Target:    cfg.Endpoint,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Track test results for summary
	type testResult struct {
		Name    string
		Status  string // "pass", "fail", "skip", "vuln"
		Details string
	}
	results := []testResult{}

	// 1. Token Audit (always runs - static analysis)
	fmt.Println("\n[1/9] Token Audit (static analysis)...")
	auditToken(cfg)
	if auditReport := loadReportFromFile(cfg.ReportFile); auditReport != nil {
		combinedReport.Vulnerabilities = append(combinedReport.Vulnerabilities, auditReport.Vulnerabilities...)
		combinedReport.Recommendations = append(combinedReport.Recommendations, auditReport.Recommendations...)
		results = append(results, testResult{"Token Audit", "done", fmt.Sprintf("%d findings", len(auditReport.Vulnerabilities))})
	}

	// 2. alg=none Bypass Test
	fmt.Println("\n[2/9] alg=none Bypass Test...")
	noneReportFile := getReportFile(cfg.ReportFile, "none")
	noneCfg := *cfg
	noneCfg.ReportFile = noneReportFile
	testNoneAlg(&noneCfg)
	if noneReport := loadReportFromFile(noneReportFile); noneReport != nil {
		combinedReport.Vulnerabilities = append(combinedReport.Vulnerabilities, noneReport.Vulnerabilities...)
		results = append(results, testResult{"alg=none Bypass", summarize(noneReport), ""})
	}

	// 3. Algorithm Confusion Test (requires pubkey)
	if cfg.PubKeyFile != "" {
		fmt.Println("\n[3/9] Algorithm Confusion Test (RS256->HS256)...")
		confReportFile := getReportFile(cfg.ReportFile, "confusion")
		confCfg := *cfg
		confCfg.ReportFile = confReportFile
		testAlgConfusion(&confCfg)
		if confReport := loadReportFromFile(confReportFile); confReport != nil {
			combinedReport.Vulnerabilities = append(combinedReport.Vulnerabilities, confReport.Vulnerabilities...)
			results = append(results, testResult{"Algorithm Confusion", summarize(confReport), ""})
		}
	} else {
		fmt.Println("\n[3/9] Algorithm Confusion Test - SKIPPED (no --pubkey provided)")
		results = append(results, testResult{"Algorithm Confusion", "skip", "No public key file provided"})
	}

	// 4. Header Injection Tests
	fmt.Println("\n[4/9] Header Injection Tests (all types)...")
	injReportFile := getReportFile(cfg.ReportFile, "injection")
	injCfg := *cfg
	injCfg.ReportFile = injReportFile
	injCfg.InjType = "all"
	testHeaderInjection(&injCfg)
	if injReport := loadReportFromFile(injReportFile); injReport != nil {
		combinedReport.Vulnerabilities = append(combinedReport.Vulnerabilities, injReport.Vulnerabilities...)
		results = append(results, testResult{"Header Injection", summarize(injReport), ""})
	}

	// 5. Claim Tampering Test (requires known secret or online endpoint)
	fmt.Println("\n[5/9] Claim Tampering Test...")
	tamperReportFile := getReportFile(cfg.ReportFile, "tamper")
	tamperCfg := *cfg
	tamperCfg.ReportFile = tamperReportFile
	testClaimTamper(&tamperCfg)
	if tamperReport := loadReportFromFile(tamperReportFile); tamperReport != nil {
		combinedReport.Vulnerabilities = append(combinedReport.Vulnerabilities, tamperReport.Vulnerabilities...)
		results = append(results, testResult{"Claim Tampering", summarize(tamperReport), ""})
	}

	// 6. Brute Force Test (requires dictionary)
	if cfg.DictFile != "" {
		fmt.Println("\n[6/9] HMAC Secret Brute Force Test...")
		bruteReportFile := getReportFile(cfg.ReportFile, "brute")
		bruteCfg := *cfg
		bruteCfg.ReportFile = bruteReportFile
		bruteForce(&bruteCfg)
		if bruteReport := loadReportFromFile(bruteReportFile); bruteReport != nil {
			if bruteReport.FoundSecret != "" {
				combinedReport.FoundSecret = bruteReport.FoundSecret
			}
			combinedReport.Attempts += bruteReport.Attempts
			combinedReport.Vulnerabilities = append(combinedReport.Vulnerabilities, bruteReport.Vulnerabilities...)
			results = append(results, testResult{"Brute Force", summarize(bruteReport), bruteReport.FoundSecret})
		}
	} else {
		fmt.Println("\n[6/9] HMAC Secret Brute Force - SKIPPED (no --dict provided)")
		results = append(results, testResult{"Brute Force", "skip", "No dictionary file provided"})
	}

	// 7. Timing Attack Test (requires online endpoint)
	if cfg.Endpoint != "" {
		fmt.Println("\n[7/9] Timing Attack Test...")
		timingReportFile := getReportFile(cfg.ReportFile, "timing")
		timingCfg := *cfg
		timingCfg.ReportFile = timingReportFile
		testTimingAttack(&timingCfg)
		if timingReport := loadReportFromFile(timingReportFile); timingReport != nil {
			combinedReport.Vulnerabilities = append(combinedReport.Vulnerabilities, timingReport.Vulnerabilities...)
			results = append(results, testResult{"Timing Attack", summarize(timingReport), ""})
		}
	} else {
		fmt.Println("\n[7/9] Timing Attack Test - SKIPPED (no --endpoint provided)")
		results = append(results, testResult{"Timing Attack", "skip", "No endpoint provided"})
	}

	// 8. Nested JWT / JWT Bomb Test
	fmt.Println("\n[8/9] Nested JWT / JWT Bomb Test...")
	nestedReportFile := getReportFile(cfg.ReportFile, "nested")
	nestedCfg := *cfg
	nestedCfg.ReportFile = nestedReportFile
	if nestedCfg.NestedDepth == 0 {
		nestedCfg.NestedDepth = 10
	}
	testNestedJWT(&nestedCfg)
	if nestedReport := loadReportFromFile(nestedReportFile); nestedReport != nil {
		combinedReport.Vulnerabilities = append(combinedReport.Vulnerabilities, nestedReport.Vulnerabilities...)
		results = append(results, testResult{"Nested JWT", summarize(nestedReport), ""})
	}

	// 9. JWKS Discovery Test (requires online endpoint)
	if cfg.Endpoint != "" {
		fmt.Println("\n[9/9] JWKS Endpoint Discovery...")
		jwksReportFile := getReportFile(cfg.ReportFile, "jwks")
		jwksCfg := *cfg
		jwksCfg.ReportFile = jwksReportFile
		discoverJWKS(&jwksCfg)
		if jwksReport := loadReportFromFile(jwksReportFile); jwksReport != nil {
			combinedReport.Vulnerabilities = append(combinedReport.Vulnerabilities, jwksReport.Vulnerabilities...)
			results = append(results, testResult{"JWKS Discovery", summarize(jwksReport), ""})
		}
	} else {
		fmt.Println("\n[9/9] JWKS Discovery - SKIPPED (no --endpoint provided)")
		results = append(results, testResult{"JWKS Discovery", "skip", "No endpoint provided"})
	}

	// Print summary
	fmt.Println("\n========================================")
	fmt.Println("  Scan Summary")
	fmt.Println("========================================")
	for _, r := range results {
		status := r.Status
		if r.Details != "" {
			status += " (" + r.Details + ")"
		}
		fmt.Printf("  %-25s %s\n", r.Name+":", status)
	}

	// Count vulnerabilities by severity
	critical := 0
	high := 0
	medium := 0
	low := 0
	info := 0
	for _, v := range combinedReport.Vulnerabilities {
		switch v.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		case "INFO":
			info++
		}
	}

	fmt.Println("========================================")
	fmt.Printf("  Total Vulnerabilities: %d\n", len(combinedReport.Vulnerabilities))
	fmt.Printf("  CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d | INFO: %d\n",
		critical, high, medium, low, info)
	fmt.Println("========================================")

	// Deduplicate recommendations
	combinedReport.Recommendations = dedupe(combinedReport.Recommendations)

	// Write combined report
	writeReport(cfg.ReportFile, combinedReport)
	fmt.Printf("\nCombined report saved to: %s\n", cfg.ReportFile)
}

// getReportFile generates a report file path for a specific test.
func getReportFile(base, test string) string {
	if base == "" {
		return test + "_report.json"
	}
	// Insert test name before .json
	if len(base) > 5 && base[len(base)-5:] == ".json" {
		return base[:len(base)-5] + "_" + test + ".json"
	}
	return base + "_" + test + ".json"
}

// loadReportFromFile loads a report from a JSON file.
func loadReportFromFile(file string) *Report {
	data, err := readFile(file)
	if err != nil {
		return nil
	}
	var report Report
	if err := unmarshalJSON(data, &report); err != nil {
		return nil
	}
	return &report
}

// summarize returns a summary status string for a report.
func summarize(report *Report) string {
	vulnCount := 0
	for _, v := range report.Vulnerabilities {
		if v.Severity == "CRITICAL" || v.Severity == "HIGH" {
			vulnCount++
		}
	}
	if vulnCount > 0 {
		return "vuln"
	}
	return "pass"
}

// dedupe removes duplicate strings from a slice.
func dedupe(items []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
