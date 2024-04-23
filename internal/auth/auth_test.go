package auth

import (
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("Error parsing empty auth header:\n%v", err)
	}

	api_key := "1234567890"

	headers.Set("Authorization", api_key)
	_, err = GetAPIKey(headers)
	if (err == ErrNoAuthHeaderIncluded) || (err == nil) {
		t.Fatalf("Error parsing malformed auth header")
	}

	headers.Set("Authorization", api_key+" ABCDE")
	_, err = GetAPIKey(headers)
	if (err == ErrNoAuthHeaderIncluded) || (err == nil) {
		t.Fatalf("Error parsing malformed header:\n%v", err)
	}

	headers.Set("Authorization", api_key+" ABCDE FGHIJ")
	_, err = GetAPIKey(headers)
	if (err == ErrNoAuthHeaderIncluded) || (err == nil) {
		t.Fatalf("Error parsing malformed header:\n%v", err)
	}

	headers.Set("Authorization", "ApiKey "+api_key)
	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("Error parsing correct auth header:\n%v", err)
	}

	if key != api_key {
		t.Fatalf("Wrong key '%s' was parsed from header; should be '%s'", key, api_key)
	}
}
