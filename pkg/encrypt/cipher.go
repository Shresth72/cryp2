package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"strings"
)

func KeyToCipher(key string) (cipher.Block, error) {
	return aes.NewCipher([]byte(key))
}

func GenerateRandomKey(length int) (string, error) {
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", buffer), nil
}

func Base8Char(bits byte) string {
	const base8Alphabet = "ABCDEFGH"

	index := int(bits)
	if index >= len(base8Alphabet) {
		return ""
	}
	return string(base8Alphabet[index])
}

func GetHexString(b []byte) string {
	hexStrings := make([]string, len(b))

	for i, val := range b {
		hexStrings[i] = fmt.Sprintf("%x", val)
	}

	return strings.Join(hexStrings, ":")
}

func GetBinaryString(b []byte) string {
	var binaryStrings []string

	for _, val := range b {
		binaryStrings = append(binaryStrings, fmt.Sprintf("%08b", val))
	}

	return strings.Join(binaryStrings, ":")
}
