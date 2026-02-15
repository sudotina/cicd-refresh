package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError bool
		errorMsg      string
	}{
		{
			name:          "valid API key",
			headers:       http.Header{"Authorization": []string{"ApiKey test-key-123"}},
			expectedKey:   "test-key-123",
			expectedError: false,
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: true,
			errorMsg:      "no authorization header included",
		},
		{
			name:          "empty authorization header",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: true,
			errorMsg:      "no authorization header included",
		},
		{
			name:          "malformed authorization header - wrong scheme",
			headers:       http.Header{"Authorization": []string{"Bearer test-key"}},
			expectedKey:   "",
			expectedError: true,
			errorMsg:      "malformed authorization header",
		},
		{
			name:          "malformed authorization header - missing key",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: true,
			errorMsg:      "malformed authorization header",
		},
		{
			name:          "valid API key with special characters",
			headers:       http.Header{"Authorization": []string{"ApiKey key_with-special.chars123"}},
			expectedKey:   "key_with-special.chars123",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if (err != nil) != tt.expectedError {
				t.Fatalf("expected error: %v, got: %v", tt.expectedError, err != nil)
			}

			if err != nil && err.Error() != tt.errorMsg {
				t.Fatalf("expected error message: %s, got: %s", tt.errorMsg, err.Error())
			}

			if key != tt.expectedKey {
				t.Fatalf("expected key: %s, got: %s", tt.expectedKey, key)
			}
		})
	}
}
