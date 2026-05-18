package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_Valid(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "my-secret-key" {
		t.Fatalf("expected key %q, got %q", "my-secret-key", key)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}

	key, err := GetAPIKey(headers)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
	if key != "" {
		t.Fatalf("expected empty key, got %q", key)
	}
}

func TestGetAPIKey_WrongScheme(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-secret-key")

	key, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if key != "" {
		t.Fatalf("expected empty key, got %q", key)
	}
}

func TestGetAPIKey_MissingKeyValue(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey")

	key, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error for malformed header, got nil")
	}
	if key != "" {
		t.Fatalf("expected empty key, got %q", key)
	}
}

func TestGetAPIKey_MultiPartKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey first-part second-part")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "first-part" {
		t.Fatalf("expected key %q, got %q", "first-part", key)
	}
}
