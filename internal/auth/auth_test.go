package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		name       string
		authHeader string
		key        string
		err        error
	}

	tests := []test{
		{name: "empty", authHeader: "", key: "", err: ErrNoAuthHeaderIncluded},
		{name: "missing key name", authHeader: "p@ssw0rd", key: "", err: errors.New("malformed authorization header")},
		{name: "wrong key name", authHeader: "apikey p@ssw0rd", key: "", err: errors.New("malformed authorization header")},
		{name: "correct", authHeader: "ApiKey p@ssw0rd", key: "p@ssw0rd", err: nil},
	}

	for _, tc := range tests {
		headers := http.Header{}
		if tc.authHeader != "" {
			headers.Set("Authorization", tc.authHeader)
		}
		key, err := GetAPIKey(headers)
		if key != tc.key || !errors.Is(err, tc.err) {
			t.Fatalf("test '%s' error\nexp: '%v', '%v'\ngot: '%v', '%v'", tc.name, tc.key, tc.err, key, err)
		}
	}
}
