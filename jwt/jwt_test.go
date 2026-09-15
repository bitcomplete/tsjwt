package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]interface{}
	}{
		{
			name: "simple claims",
			payload: map[string]interface{}{
				"sub": "user123",
				"aud": "myapp",
				"exp": 1234567890,
			},
		},
		{
			name: "nested structure",
			payload: map[string]interface{}{
				"sub": "user456",
				"data": map[string]interface{}{
					"key": "value",
				},
			},
		},
		{
			name: "with array",
			payload: map[string]interface{}{
				"roles": []string{"admin", "user"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			token, err := Sign(key, "test-kid", tt.payload)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			payload, err := Verify(&key.PublicKey, token)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(payload, &result); err != nil {
				t.Fatalf("unmarshal result failed: %v", err)
			}

			var expected map[string]interface{}
			payloadJSON, _ := json.Marshal(tt.payload)
			if err := json.Unmarshal(payloadJSON, &expected); err != nil {
				t.Fatalf("unmarshal expected failed: %v", err)
			}

			// Compare as JSON strings for consistent comparison
			resultJSON, _ := json.Marshal(result)
			expectedJSON, _ := json.Marshal(expected)
			if string(resultJSON) != string(expectedJSON) {
				t.Errorf("payload mismatch:\ngot:      %s\nexpected: %s", resultJSON, expectedJSON)
			}
		})
	}
}

func TestVerifyFailures(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	payload := map[string]string{"sub": "user123"}
	token, _ := Sign(key, "kid1", payload)

	tests := []struct {
		name       string
		token      string
		publicKey  *ecdsa.PublicKey
		expectedErr error
	}{
		{
			name:        "tampered payload",
			token:       tamperedPayload(token),
			publicKey:   &key.PublicKey,
			expectedErr: ErrSignature,
		},
		{
			name:        "tampered signature",
			token:       tamperedSignature(token),
			publicKey:   &key.PublicKey,
			expectedErr: ErrSignature,
		},
		{
			name:        "wrong key",
			token:       token,
			publicKey:   &otherKey.PublicKey,
			expectedErr: ErrSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(tt.publicKey, tt.token)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if err != tt.expectedErr {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestParseRejectsInvalidSegmentCount(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "one segment",
			token: "eyJhbGciOiJFUzI1NiJ9",
		},
		{
			name:  "two segments",
			token: "eyJhbGciOiJFUzI1NiJ9.payload",
		},
		{
			name:  "four segments",
			token: "eyJhbGciOiJFUzI1NiJ9.payload.sig.extra",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse(tt.token)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if err != ErrMalformed {
				t.Errorf("expected ErrMalformed, got %v", err)
			}
		})
	}
}

func TestParseRejectsNonBase64Header(t *testing.T) {
	// Deliberately invalid base64
	token := "!!!invalid!!!.payload.sig"

	_, _, err := Parse(token)
	if err == nil {
		t.Error("expected error, got nil")
	}
	if err != ErrMalformed {
		t.Errorf("expected ErrMalformed, got %v", err)
	}
}

func TestParseRejectsWrongAlgorithm(t *testing.T) {
	tests := []struct {
		name   string
		alg    string
	}{
		{
			name: "alg none",
			alg:  "none",
		},
		{
			name: "alg HS256",
			alg:  "HS256",
		},
		{
			name: "alg RS256",
			alg:  "RS256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build token with wrong algorithm manually
			hdr := Header{Alg: tt.alg, Typ: Typ, Kid: "test"}
			hdrJSON, _ := json.Marshal(hdr)
			payload := []byte(`{"sub":"user"}`)

			// Create a fake token string (doesn't need to verify, just parse)
			token := b64(hdrJSON) + "." + b64(payload) + ".fakesig"

			_, _, err := Parse(token)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if err != ErrAlgorithm {
				t.Errorf("expected ErrAlgorithm, got %v", err)
			}
		})
	}
}

func TestParseRejectsBadTyp(t *testing.T) {
	tests := []struct {
		name string
		typ  string
	}{
		{
			name: "typ NOTJWT",
			typ:  "NOTJWT",
		},
		{
			name: "typ at (lowercase of JWT)",
			typ:  "at",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := Header{Alg: Alg, Typ: tt.typ, Kid: "test"}
			hdrJSON, _ := json.Marshal(hdr)
			payload := []byte(`{"sub":"user"}`)
			token := b64(hdrJSON) + "." + b64(payload) + ".fakesig"

			_, _, err := Parse(token)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if err != ErrMalformed {
				t.Errorf("expected ErrMalformed, got %v", err)
			}
		})
	}
}

func TestVerifyRejectsBadSignatureLength(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := map[string]string{"sub": "user"}
	token, _ := Sign(key, "kid", payload)

	// Replace signature with one that's not 64 bytes
	parts := strings.Split(token, ".")
	badSig := base64.RawURLEncoding.EncodeToString([]byte("tooshort"))
	badToken := parts[0] + "." + parts[1] + "." + badSig

	_, err := Verify(&key.PublicKey, badToken)
	if err == nil {
		t.Error("expected error, got nil")
	}
	if err != ErrMalformed {
		t.Errorf("expected ErrMalformed, got %v", err)
	}
}

// Helper function to tamper with payload
func tamperedPayload(token string) string {
	parts := strings.Split(token, ".")
	var payload map[string]string
	rawPayload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(rawPayload, &payload)
	payload["sub"] = "different-user"
	tamperedPayloadJSON, _ := json.Marshal(payload)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(tamperedPayloadJSON) + "." + parts[2]
}

// Helper function to tamper with signature
func tamperedSignature(token string) string {
	parts := strings.Split(token, ".")
	rawSig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	// Flip first bit of signature
	if len(rawSig) > 0 {
		rawSig[0] ^= 0x01
	}
	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(rawSig)
}

// b64 and unb64 helpers for building test tokens
func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
