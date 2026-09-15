package tsjwt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClaimsRoundTripJSON(t *testing.T) {
	original := Claims{
		Issuer:    "https://example.com",
		Subject:   "user123",
		Audience:  "myapp",
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		Expiry:    time.Now().Add(time.Hour).Unix(),
		ID:        "jti123",
		Email:     "user@example.com",
		Name:      "John Doe",
		Node:      "node1",
		Tenant:    "tenant1",
		Tenants:   []string{"tenant1", "tenant2"},
		Roles:     []string{"admin", "user"},
		Groups:    []string{"group1", "group2"},
		Extra: map[string]any{
			"custom_claim": "custom_value",
			"nested": map[string]any{
				"key": "value",
			},
			"array": []string{"a", "b", "c"},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal back
	var recovered Claims
	if err := json.Unmarshal(data, &recovered); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify all standard fields
	if recovered.Issuer != original.Issuer {
		t.Errorf("Issuer mismatch: %q != %q", recovered.Issuer, original.Issuer)
	}
	if recovered.Subject != original.Subject {
		t.Errorf("Subject mismatch: %q != %q", recovered.Subject, original.Subject)
	}
	if recovered.Audience != original.Audience {
		t.Errorf("Audience mismatch: %q != %q", recovered.Audience, original.Audience)
	}
	if recovered.ID != original.ID {
		t.Errorf("ID mismatch: %q != %q", recovered.ID, original.ID)
	}
	if recovered.Email != original.Email {
		t.Errorf("Email mismatch: %q != %q", recovered.Email, original.Email)
	}
	if recovered.Name != original.Name {
		t.Errorf("Name mismatch: %q != %q", recovered.Name, original.Name)
	}
	if recovered.Tenant != original.Tenant {
		t.Errorf("Tenant mismatch: %q != %q", recovered.Tenant, original.Tenant)
	}

	// Verify Extra is preserved
	if len(recovered.Extra) != len(original.Extra) {
		t.Errorf("Extra length mismatch: %d != %d", len(recovered.Extra), len(original.Extra))
	}

	// Verify specific Extra claims
	if val, ok := recovered.Extra["custom_claim"]; !ok || val != "custom_value" {
		t.Errorf("custom_claim not preserved: got %v", val)
	}

	// Verify nested Extra
	if nested, ok := recovered.Extra["nested"].(map[string]any); !ok || nested["key"] != "value" {
		t.Errorf("nested claim not preserved correctly: got %v", recovered.Extra["nested"])
	}
}

func TestClaimsMarshalJSONRefusesReservedKeyInExtra(t *testing.T) {
	tests := []struct {
		name     string
		extraKey string
	}{
		{"shadows iss", "iss"},
		{"shadows sub", "sub"},
		{"shadows aud", "aud"},
		{"shadows iat", "iat"},
		{"shadows nbf", "nbf"},
		{"shadows exp", "exp"},
		{"shadows jti", "jti"},
		{"shadows email", "email"},
		{"shadows name", "name"},
		{"shadows node", "node"},
		{"shadows tenant", ClaimTenant},
		{"shadows tenants", ClaimTenants},
		{"shadows roles", ClaimRoles},
		{"shadows groups", ClaimGroups},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := Claims{
				Issuer:   "https://example.com",
				Subject:  "user123",
				Audience: "myapp",
				ID:       "jti123",
				Extra: map[string]any{
					tt.extraKey: "should_fail",
				},
			}

			_, err := json.Marshal(claims)
			if err == nil {
				t.Error("expected error for reserved key, got nil")
			}
			// json.Marshal wraps the error from MarshalJSON
			if !strings.Contains(err.Error(), "extra claim") || !strings.Contains(err.Error(), "shadows") {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}

func TestClaimsMarshalJSONAllowsNonReservedExtra(t *testing.T) {
	claims := Claims{
		Issuer:   "https://example.com",
		Subject:  "user123",
		Audience: "myapp",
		ID:       "jti123",
		Extra: map[string]any{
			"custom1": "value1",
			"custom2": 42,
			"custom3": []string{"a", "b"},
		},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify the extra claims are in the output
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal result failed: %v", err)
	}

	if val, ok := result["custom1"]; !ok || val != "value1" {
		t.Errorf("custom1 not in result: got %v", val)
	}
	if val, ok := result["custom2"]; !ok || val != float64(42) {
		t.Errorf("custom2 not in result: got %v", val)
	}
}

func TestClaimsUnmarshalJSONPreservesExtra(t *testing.T) {
	jsonData := []byte(`{
		"iss": "https://example.com",
		"sub": "user123",
		"aud": "myapp",
		"iat": 1234567890,
		"exp": 1234568890,
		"jti": "jti123",
		"custom_claim": "custom_value",
		"another_claim": 42,
		"array_claim": ["x", "y"]
	}`)

	var claims Claims
	if err := json.Unmarshal(jsonData, &claims); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if claims.Issuer != "https://example.com" {
		t.Errorf("Issuer not parsed: got %q", claims.Issuer)
	}
	if claims.Subject != "user123" {
		t.Errorf("Subject not parsed: got %q", claims.Subject)
	}

	// Verify Extra contains non-standard claims
	if claims.Extra == nil {
		t.Error("Extra is nil")
	}
	if val, ok := claims.Extra["custom_claim"]; !ok || val != "custom_value" {
		t.Errorf("custom_claim not in Extra: got %v", val)
	}
	if val, ok := claims.Extra["another_claim"]; !ok || val != float64(42) {
		t.Errorf("another_claim not in Extra: got %v", val)
	}
}

func TestClaimsExtraDoesNotIncludeReservedClaims(t *testing.T) {
	jsonData := []byte(`{
		"iss": "https://example.com",
		"sub": "user123",
		"aud": "myapp",
		"iat": 1234567890,
		"exp": 1234568890,
		"jti": "jti123",
		"email": "user@example.com",
		"tenant": "tenant1",
		"roles": ["admin"],
		"custom": "value"
	}`)

	var claims Claims
	if err := json.Unmarshal(jsonData, &claims); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Reserved claims should NOT be in Extra
	if _, ok := claims.Extra["iss"]; ok {
		t.Error("iss should not be in Extra")
	}
	if _, ok := claims.Extra["sub"]; ok {
		t.Error("sub should not be in Extra")
	}
	if _, ok := claims.Extra["email"]; ok {
		t.Error("email should not be in Extra")
	}
	if _, ok := claims.Extra["tenant"]; ok {
		t.Error("tenant should not be in Extra")
	}

	// Custom claim should be in Extra
	if val, ok := claims.Extra["custom"]; !ok || val != "value" {
		t.Errorf("custom claim not in Extra: got %v", val)
	}
}

func TestClaimsExpiresAt(t *testing.T) {
	ts := int64(1234567890)
	claims := Claims{Expiry: ts}
	expTime := claims.ExpiresAt()

	if expTime.Unix() != ts {
		t.Errorf("ExpiresAt returned wrong time: %d != %d", expTime.Unix(), ts)
	}
}

func TestClaimsHasRole(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		looking  string
		expected bool
	}{
		{
			name:     "role present",
			roles:    []string{"admin", "user"},
			looking:  "admin",
			expected: true,
		},
		{
			name:     "role not present",
			roles:    []string{"admin", "user"},
			looking:  "viewer",
			expected: false,
		},
		{
			name:     "empty roles",
			roles:    []string{},
			looking:  "admin",
			expected: false,
		},
		{
			name:     "case sensitive",
			roles:    []string{"admin"},
			looking:  "Admin",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := Claims{Roles: tt.roles}
			if result := claims.HasRole(tt.looking); result != tt.expected {
				t.Errorf("HasRole(%q) = %v, expected %v", tt.looking, result, tt.expected)
			}
		})
	}
}

func TestClaimsEmptyExtraDoesNotAppearInJSON(t *testing.T) {
	claims := Claims{
		Issuer:   "https://example.com",
		Subject:  "user123",
		Audience: "myapp",
		ID:       "jti123",
		Extra:    make(map[string]any), // Empty
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal result failed: %v", err)
	}

	// Check that no custom claims are present (Extra should not add any keys)
	// Standard fields may be present (iss, sub, aud, iat, exp, nbf, jti, etc)
	for key := range result {
		// All keys in result should be from the standard reserved set
		if key != "iss" && key != "sub" && key != "aud" && key != "iat" && key != "nbf" &&
			key != "exp" && key != "jti" && key != "email" && key != "name" && key != "node" &&
			key != "tenant" && key != "tenants" && key != "roles" && key != "groups" {
			t.Errorf("unexpected key in result: %s", key)
		}
	}
}
