package main

import (
	"testing"

	"github.com/shresth72/cry/pkg/encrypt"
	"github.com/stretchr/testify/assert"
)

var withSubmit = true

func TestDebugEncryptDecrypt(t *testing.T) {
	type testCase struct {
		masterKey string
		iv        string
		password  string
		expectedE string
		expectedD string
	}

	const masterKey = "kjhgfdsaqwertyuioplkjhgfdsaqwert"
	const iv = "1234567812345678"

	tests := []testCase{
		{
			masterKey,
			iv,
			"k33pThisPasswordSafe",
			encrypt.Encrypt("k33pThisPasswordSafe", masterKey, iv),
			"k33pThisPasswordSafe",
		},
		{masterKey, iv, "12345", encrypt.Encrypt("12345", masterKey, iv), "12345"},
		{
			masterKey,
			iv,
			"thePasswordOnMyLuggage",
			encrypt.Encrypt("thePasswordOnMyLuggage", masterKey, iv),
			"thePasswordOnMyLuggage",
		},
		{
			masterKey,
			iv,
			"pizza_the_HUt",
			encrypt.Encrypt("pizza_the_HUt", masterKey, iv),
			"pizza_the_HUt",
		},
		{
			masterKey,
			iv,
			"aNewPassword",
			encrypt.Encrypt("aNewPassword", masterKey, iv),
			"aNewPassword",
		},
		{
			masterKey,
			iv,
			"edgeCaseTest",
			encrypt.Encrypt("edgeCaseTest", masterKey, iv),
			"edgeCaseTest",
		},
	}

	for _, test := range tests {
		encrypted, decrypted := debugEncryptDecrypt(test.masterKey, test.iv, test.password)
		assert.Equal(t, test.expectedE, encrypted)
		assert.Equal(t, test.expectedD, decrypted)
	}
}
