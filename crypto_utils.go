package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// generateRSAKeyPair generates an RSA key pair of the specified bit size.
func generateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// publicKeyToJWK converts an RSA public key to a JWK map.
func publicKeyToJWK(pub *rsa.PublicKey, kid string) (map[string]interface{}, error) {
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}, nil
}

// publicKeyToPEM converts an RSA public key to PEM-encoded SPKI format.
func publicKeyToPEM(pub *rsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	return string(pemBytes), nil
}

// publicKeyToPKCS1PEM converts an RSA public key to PKCS1 PEM format.
// Used for algorithm confusion attacks where the server stores the key in PKCS1 format.
func publicKeyToPKCS1PEM(pub *rsa.PublicKey) (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	})
	return string(pemBytes), nil
}

// generateSelfSignedCert creates a self-signed X.509 certificate for the given RSA key.
func generateSelfSignedCert(priv *rsa.PrivateKey) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "jwtblast-attacker"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	return certBytes, nil
}

// loadPublicKeyFromFile loads an RSA public key from a PEM file.
// Supports both SPKI (BEGIN PUBLIC KEY) and PKCS1 (BEGIN RSA PUBLIC KEY) formats.
func loadPublicKeyFromFile(file string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", file)
	}

	var pub *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
		}
		var ok bool
		pub, ok = key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA")
		}
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 public key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
	return pub, nil
}

// loadPrivateKeyFromFile loads an RSA private key from a PEM file.
func loadPrivateKeyFromFile(file string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", file)
	}

	var priv *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		priv, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
	return priv, nil
}

// createJWKS creates a JWKS (JSON Web Key Set) map from an RSA public key.
func createJWKS(pub *rsa.PublicKey, kid string) (map[string]interface{}, error) {
	jwk, err := publicKeyToJWK(pub, kid)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}, nil
}

// saveJWKSToFile writes a JWKS map to a file as JSON.
func saveJWKSToFile(jwks map[string]interface{}, file string) error {
	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0644)
}
