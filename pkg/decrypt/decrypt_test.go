package decrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHexBytes(t *testing.T) {
	type testCase struct {
		input      string
		expected   []byte
		shouldFail bool
	}

	tests := []testCase{
		{"48:65:6c:6c:6f", []byte("Hello"), false},             // Hex for "Hello"
		{"57:6f:72:6c:64", []byte("World"), false},             // Hex for "World"
		{"50:61:73:73:77:6f:72:64", []byte("Password"), false}, // Hex for "Password"
		{"ZZ:YY:XX", nil, true},                                // Invalid hex
		{"4c:65:61:72:6e:69:6e:67", []byte("Learning"), false}, // Hex for "Learning"
		{"54:65:73:74", []byte("Test"), false},                 // Hex for "Test"
	}

	for _, test := range tests {
		result, _ := GetHexBytes(test.input)
		assert.Equal(t, test.expected, result)
	}
}
