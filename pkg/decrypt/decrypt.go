package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"log"
	"strings"
)

func Decrypt(cipherText, key, iv string) string {
	blockCipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Println(err)
		return ""
	}

	stream := cipher.NewCTR(blockCipher, []byte(iv))
	bytes, err := hex.DecodeString(cipherText)
	if err != nil {
		log.Println(err)
		return ""
	}

	stream.XORKeyStream(bytes, bytes)
	return string(bytes)
}

func GetHexBytes(s string) ([]byte, error) {
	hexString := strings.Split(s, ":")

	var result []byte
	for _, val := range hexString {
		bytes, err := hex.DecodeString(val)
		if err != nil {
			return nil, err
		}
		result = append(result, bytes...)
	}

	return result, nil
}
