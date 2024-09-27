package encrypt

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyToCipher(t *testing.T) {
	type testCase struct {
		key        string
		shouldFail bool
	}

	tests := []testCase{
		{"thisIsMySecretKeyIHopeNoOneFinds", false}, // Valid key
		{"short", true}, // Too short key
		{"an extremely long key that exceeds the block size", true}, // Too long key
		{
			"thisIsA32ByteKeyForAES256Testing!",
			true,
		}, // Valid 32-byte key for AES-256
		{
			"valid16ByteKeyHere",
			true,
		}, // Valid 16-byte key for AES-128
		{
			"invalid-key",
			true,
		}, // Invalid key, not the correct length
		{"ThisIsA24ByteKeyForAES192Testing", false}, // Valid key for AES-192
	}

	for _, test := range tests {
		_, err := KeyToCipher(test.key)
		assert.Equal(t, test.shouldFail, err != nil)
	}
}

func TestGenerateRandomKey(t *testing.T) {
	rand.Seed(0)

	type testCase struct {
		length     int
		shouldFail bool
		expected   string
	}

	tests := []testCase{
		{
			16,
			false,
			"0194fdc2fa2ffcc041d3ff12045b73c8",
		}, // Expected output for 16 bytes
		{
			32,
			false,
			"6e4ff95ff662a5eee82abdf44a2d0b75fb180daf48a79ee0b10d394651850fd4",
		}, // Expected output for 32 bytes
		{8, false, "a178892ee285ece1"}, // Expected output for 8 bytes
		{
			64,
			false,
			"511455780875d64ee2d3d0d0de6bf8f9b44ce85ff044c6b1f83b8e883bbf857aab99c5b252c7429c32f3a8aeb79ef856f659c18f0dcecc77c75e7a81bfde275f",
		}, // Expected output for 64 bytes
	}

	for _, test := range tests {
		key, err := GenerateRandomKey(test.length)
		assert.Equal(t, test.shouldFail, err != nil)
		assert.Equal(t, test.expected, key)
	}
}

func TestBase8Char(t *testing.T) {
	type testCase struct {
		bits     byte
		expected string
	}

	tests := []testCase{
		{0b000, "A"},     // 0000 -> A
		{0b001, "B"},     // 0001 -> B
		{0b010, "C"},     // 0010 -> C
		{0b011, "D"},     // 0011 -> D
		{0b100, "E"},     // 0100 -> E
		{0b101, "F"},     // 0101 -> F
		{0b110, "G"},     // 0110 -> G
		{0b111, "H"},     // 0111 -> H
		{0b101, "F"},     // Valid additional case
		{0b1111, ""},     // 4-bit, out of range
		{0b1000, ""},     // 1000 is out of bounds
		{0b11111111, ""}, // Max byte value, out of bounds
	}

	for _, test := range tests {
		result := Base8Char(test.bits)
		assert.Equal(t, test.expected, result)
	}
}

func TestGetHexString(t *testing.T) {
	type testCase struct {
		input    []byte
		expected string
	}

	tests := []testCase{
		{[]byte("Hello"), "48:65:6c:6c:6f"},     // Hex for "Hello"
		{[]byte("World"), "57:6f:72:6c:64"},     // Hex for "World"
		{[]byte("GoLang"), "47:6f:4c:61:6e:67"}, // Hex for "GoLang"
		{[]byte("Passly"), "50:61:73:73:6c:79"}, // Hex for "Passly"
	}

	for _, test := range tests {
		result := GetHexString(test.input)
		assert.Equal(t, test.expected, result)
	}
}

func TestGetBinaryString(t *testing.T) {
	type testCase struct {
		input    []byte
		expected string
	}

	tests := []testCase{
		{
			[]byte("Hello"),
			"01001000:01100101:01101100:01101100:01101111",
		}, // Binary for "Hello"
		{
			[]byte("World"),
			"01010111:01101111:01110010:01101100:01100100",
		}, // Binary for "World"
		{
			[]byte("GoLang"),
			"01000111:01101111:01001100:01100001:01101110:01100111",
		}, // Binary for "GoLang"
		{
			[]byte("Passly"),
			"01010000:01100001:01110011:01110011:01101100:01111001",
		}, // Binary for "Passly"
	}

	for _, test := range tests {
		result := GetBinaryString(test.input)
		assert.Equal(t, test.expected, result)
	}
}
