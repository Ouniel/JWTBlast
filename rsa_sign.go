package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// signWithRS256 signs the signing input using RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
func signWithRS256(signingInput string, privKey *rsa.PrivateKey) (string, error) {
	h := sha256.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("RSA signing failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// constructRSAJWT builds a complete JWT with RS256 signing from header and payload maps.
func constructRSAJWT(header, payload map[string]interface{}, privKey *rsa.PrivateKey) (string, error) {
	headerEnc, err := encodeTokenPart(header)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}
	payloadEnc, err := encodeTokenPart(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}
	signingInput := headerEnc + "." + payloadEnc
	sigEnc, err := signWithRS256(signingInput, privKey)
	if err != nil {
		return "", err
	}
	return signingInput + "." + sigEnc, nil
}

// constructRSAJWTWithRawPayload builds a JWT with RS256 signing, preserving the
// original base64 payload encoding.
func constructRSAJWTWithRawPayload(header map[string]interface{}, payloadB64 string, privKey *rsa.PrivateKey) (string, error) {
	headerEnc, err := encodeTokenPart(header)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}
	signingInput := headerEnc + "." + payloadB64
	sigEnc, err := signWithRS256(signingInput, privKey)
	if err != nil {
		return "", err
	}
	return signingInput + "." + sigEnc, nil
}
