package main

import (
	"github.com/shresth72/cry/pkg/decrypt"
	"github.com/shresth72/cry/pkg/encrypt"
)

// Shared Key (Symmetric Encryption)
func debugEncryptDecrypt(masterKey, iv, password string) (string, string) {
	encrypted := encrypt.Encrypt(password, masterKey, iv)
	decrypted := decrypt.Decrypt(encrypted, masterKey, iv)

	return encrypted, decrypted
}
