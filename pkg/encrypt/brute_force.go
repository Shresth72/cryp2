package encrypt

import (
	"encoding/binary"
	"errors"
	"math"
)

func AlphabetSize(numBits int) float64 {
	return math.Pow(2, float64(numBits))
}

func FindKey(encrypted []byte, decrypted string) ([]byte, error) {
	for i := 0; i < int(math.Pow(2, 24)); i++ {
		key := intToBytes(i)
		decryptedMsg := crypt(encrypted, key)

		if string(decryptedMsg) == decrypted {
			return key, nil
		}
	}

	return nil, errors.New("key not found")
}

func crypt(data, key []byte) []byte {
	final := []byte{}
	for i, d := range data {
		final = append(final, d^key[i])
	}

	return final
}

func intToBytes(num int) []byte {
	byteArray := make([]byte, 4)
	binary.BigEndian.PutUint32(byteArray, uint32(num))
	return byteArray[1:]
}
