package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"sort"
	"time"
)

// timingTestConfig holds parameters for a timing attack test.
type timingTestConfig struct {
	Name        string
	Description string
	TokenGen    func(base string) []string
}

// testTimingAttack measures response time differences for different token
// variations to detect timing side-channel vulnerabilities in signature
// verification. A non-constant-time comparison leaks information about
// the expected signature, enabling byte-by-byte signature recovery.
func testTimingAttack(cfg *Config) {
	if cfg.Endpoint == "" {
		fmt.Println("[Timing Attack] This test requires an online endpoint. Use --endpoint flag.")
		return
	}

	if !confirmOnline(cfg) {
		return
	}

	samples := cfg.Samples
	if samples <= 0 {
		samples = 50
	}

	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = 0.05 // 5% relative difference
	}

	header, payload, sig, err := decodeTokenParts(cfg.Token)
	if err != nil {
		log.Fatalf("Failed to decode token: %v", err)
	}

	report := Report{}
	vulnerable := false

	// Test 1: Valid signature vs. random signature
	fmt.Printf("[Timing] Test 1: Valid vs. random signature (%d samples each)\n", samples)
	validTimes, randomTimes := measureSignatureTiming(cfg, cfg.Token, header, payload, sig, samples)

	if len(validTimes) > 0 && len(randomTimes) > 0 {
		validAvg := average(validTimes)
		randomAvg := average(randomTimes)
		diffPct := math.Abs(validAvg-randomAvg) / validAvg * 100

		fmt.Printf("  Valid sig avg:  %.2fms\n  Random sig avg: %.2fms\n  Difference:     %.2f%%\n",
			validAvg, randomAvg, diffPct)

		if diffPct > threshold*100 {
			vulnerable = true
			addResult(&report, VulnerabilityResult{
				Name:        "Timing Side-Channel: Signature Comparison",
				Category:    "Timing Attack",
				Severity:    "HIGH",
				Description: fmt.Sprintf("Signature verification shows %.2f%% timing difference between valid and random signatures. "+
					"This indicates non-constant-time comparison, enabling byte-by-byte signature recovery.", diffPct),
				Confirmed: true,
				Details: map[string]string{
					"valid_avg_ms":   fmt.Sprintf("%.2f", validAvg),
					"random_avg_ms":  fmt.Sprintf("%.2f", randomAvg),
					"difference_pct": fmt.Sprintf("%.2f", diffPct),
					"samples":        fmt.Sprintf("%d", samples),
				},
			})
		} else {
			fmt.Printf("  [SAFE] Timing difference below threshold (%.2f%% < %.2f%%)\n", diffPct, threshold*100)
		}
	}

	// Test 2: Byte-by-byte signature prefix timing
	fmt.Printf("[Timing] Test 2: Byte-by-byte signature prefix (%d samples each)\n", samples)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(sig)
	if len(sigBytes) > 0 {
		prefixTiming := measurePrefixTiming(cfg, header, payload, sigBytes, samples)

		if len(prefixTiming) > 1 {
			maxVariance := findMaxVariance(prefixTiming)
			fmt.Printf("  Max timing variance across prefix lengths: %.2fms\n", maxVariance)

			if maxVariance > threshold*100 {
				vulnerable = true
				addResult(&report, VulnerabilityResult{
					Name:        "Timing Side-Channel: Prefix Comparison",
					Category:    "Timing Attack",
					Severity:    "CRITICAL",
					Description: fmt.Sprintf("Byte-by-byte prefix timing analysis reveals %.2fms variance. "+
						"This strongly suggests non-constant-time comparison with early exit, "+
						"enabling full signature recovery via timing oracle.", maxVariance),
					Confirmed: true,
					Details: map[string]string{
						"max_variance_ms": fmt.Sprintf("%.2f", maxVariance),
						"samples":         fmt.Sprintf("%d", samples),
					},
				})
			}
		}
	}

	// Test 3: Claim validation timing
	fmt.Printf("[Timing] Test 3: Claim validation timing (%d samples each)\n", samples)
	claimTimes := measureClaimTiming(cfg, cfg.Token, header, payload, samples)
	if len(claimTimes) > 0 {
		expAvg := average(claimTimes)
		fmt.Printf("  Claim validation avg: %.2fms\n", expAvg)
	}

	if !vulnerable {
		addResult(&report, newResult(
			"Timing Attack (not vulnerable)",
			"Timing Attack",
			"INFO",
			"No significant timing differences detected. Signature comparison appears to use constant-time comparison.",
		))
	}

	report.Recommendations = append(report.Recommendations,
		"Use constant-time comparison (e.g., crypto/subtle.ConstantTimeCompare in Go, hmac.compare_digest in Python)",
		"Never use == or bytes.Equal for signature comparison",
		"Add random delay jitter to mask residual timing differences",
		"Use HMAC library functions that enforce constant-time comparison",
	)
	writeReport(cfg.ReportFile, report)
}

// measureSignatureTiming sends the valid token and random-signature tokens,
// measuring response time for each.
func measureSignatureTiming(cfg *Config, validToken string, header, payload map[string]interface{}, sig string, samples int) (validTimes, randomTimes []float64) {
	// Measure valid token timing
	for i := 0; i < samples; i++ {
		start := time.Now()
		sendTokenAndCheck(cfg, validToken)
		elapsed := time.Since(start).Seconds() * 1000
		validTimes = append(validTimes, elapsed)
	}

	// Measure random signature timing
	headerEnc, _ := encodeTokenPart(header)
	payloadEnc, _ := encodeTokenPart(payload)

	for i := 0; i < samples; i++ {
		randomSig := generateRandomSignature()
		forged := headerEnc + "." + payloadEnc + "." + randomSig
		start := time.Now()
		sendTokenAndCheck(cfg, forged)
		elapsed := time.Since(start).Seconds() * 1000
		randomTimes = append(randomTimes, elapsed)
	}

	return
}

// measurePrefixTiming measures timing for signatures with increasing correct prefix lengths.
func measurePrefixTiming(cfg *Config, header, payload map[string]interface{}, sigBytes []byte, samples int) map[int]float64 {
	headerEnc, _ := encodeTokenPart(header)
	payloadEnc, _ := encodeTokenPart(payload)

	results := make(map[int]float64)
	prefixLengths := []int{0, 1, 4, 8, 16, 32}
	if len(sigBytes) < 32 {
		prefixLengths = []int{0, 1, 4, 8, 16}
	}

	for _, prefixLen := range prefixLengths {
		if prefixLen > len(sigBytes) {
			continue
		}

		var times []float64
		for i := 0; i < samples; i++ {
			// Build signature with correct prefix + random suffix
			correctPrefix := sigBytes[:prefixLen]
			randomSuffix := make([]byte, len(sigBytes)-prefixLen)
			for j := range randomSuffix {
				randomSuffix[j] = byte(time.Now().UnixNano() & 0xFF)
			}
			modifiedSig := append(correctPrefix, randomSuffix...)
			sigEnc := base64.RawURLEncoding.EncodeToString(modifiedSig)
			forged := headerEnc + "." + payloadEnc + "." + sigEnc

			start := time.Now()
			sendTokenAndCheck(cfg, forged)
			elapsed := time.Since(start).Seconds() * 1000
			times = append(times, elapsed)
		}

		if len(times) > 0 {
			results[prefixLen] = average(times)
			fmt.Printf("  Prefix %2d bytes: avg %.2fms\n", prefixLen, results[prefixLen])
		}
	}

	return results
}

// measureClaimTiming measures timing for tokens with different claim values.
func measureClaimTiming(cfg *Config, validToken string, header, payload map[string]interface{}, samples int) []float64 {
	var times []float64

	// Test with modified expiration (future)
	payloadCopy := copyHeader(payload)
	payloadCopy["exp"] = time.Now().Add(1 * time.Hour).Unix()

	headerEnc, _ := encodeTokenPart(header)
	payloadEnc, _ := encodeTokenPart(payloadCopy)

	// Use random signature to isolate claim validation timing from signature timing
	for i := 0; i < samples; i++ {
		randomSig := generateRandomSignature()
		forged := headerEnc + "." + payloadEnc + "." + randomSig

		start := time.Now()
		sendTokenAndCheck(cfg, forged)
		elapsed := time.Since(start).Seconds() * 1000
		times = append(times, elapsed)
	}

	return times
}

// generateRandomSignature creates a random base64url-encoded signature.
func generateRandomSignature() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> uint(i%8))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// average calculates the mean of a slice of float64 values.
func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// median calculates the median of a slice of float64 values.
func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

// findMaxVariance finds the maximum timing variance across different prefix lengths.
func findMaxVariance(timings map[int]float64) float64 {
	if len(timings) < 2 {
		return 0
	}

	var values []float64
	for _, v := range timings {
		values = append(values, v)
	}

	if len(values) < 2 {
		return 0
	}

	sort.Float64s(values)
	return values[len(values)-1] - values[0]
}
