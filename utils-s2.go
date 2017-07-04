package main

import (
	"bytes"
	"crypto/aes"
	"math/rand"
	"time"
)

func pkcs7(message []byte, bs int) []byte {
	if len(message)%bs == 0 {
		result := make([]byte, 0, len(message)+bs)
		for _, b := range message {
			result = append(result, b)
		}
		for i := 0; i < bs; i++ {
			result = append(result, byte(bs))
		}
		return result
	}
	residue := bs - (len(message) % bs)
	result := make([]byte, 0, len(message)+residue)
	for _, b := range message {
		result = append(result, b)
	}
	for i := 0; i < residue; i++ {
		result = append(result, byte(residue))
	}
	return result
}

func encryptAesEcb(plaintext, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	bs := block.BlockSize()

	if len(plaintext) != bs {
		panic("Need a multiple of the blocksize")
	}

	ciphertext := make([]byte, bs)
	block.Encrypt(ciphertext, plaintext)
	return ciphertext
}

func decryptAesEcb(ciphertext, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	bs := block.BlockSize()

	if len(ciphertext) != bs {
		panic("Need a multiple of the blocksize")
	}

	plaintext := make([]byte, bs)
	block.Decrypt(plaintext, ciphertext)
	return plaintext
}

func decryptAesCbc(ciphertext, key, iv []byte) []byte {
	bs := len(key)
	if len(ciphertext)%bs != 0 {
		panic("Need a multiple of the blocksize")
	}

	plaintext := make([]byte, 0, len(ciphertext))
	buffer := make([]byte, bs)
	copy(buffer, iv)
	for len(ciphertext) > 0 {
		cb := ciphertext[:bs]
		ciphertext = ciphertext[bs:]

		decryption := decryptAesEcb(cb, key)
		plaintext = append(plaintext, fixedXor(decryption, buffer)...)
		buffer = cb
	}
	return plaintext
}

func encryptAesCbc(plaintext, key, iv []byte) []byte {
	bs := len(key)
	if len(plaintext)%bs != 0 {
		panic("Need a multiple of the blocksize")
	}

	ciphertext := make([]byte, 0, len(plaintext))
	buffer := make([]byte, bs)
	copy(buffer, iv)
	for len(plaintext) > 0 {
		pb := plaintext[:bs]
		plaintext = plaintext[bs:]

		encryption := encryptAesEcb(fixedXor(pb, buffer), key)
		ciphertext = append(ciphertext, encryption...)
		buffer = encryption
	}
	return ciphertext
}

func randomBytes(n int) []byte {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)

	key := make([]byte, n)
	for i := range key {
		key[i] = byte(r.Intn(256))
	}
	return key
}

func randomAESKey() []byte {
	return randomBytes(16)
}

func encryptAesEcbMultiblock(plaintext, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	bs := block.BlockSize()

	if len(plaintext)%bs != 0 {
		panic("Need a multiple of the blocksize")
	}

	ciphertext := make([]byte, 0, len(plaintext))
	for len(plaintext) > 0 {
		cb := make([]byte, bs)
		block.Encrypt(cb, plaintext)
		plaintext = plaintext[bs:]
		ciphertext = append(ciphertext, cb...)
	}

	return ciphertext
}

func encryptionOracle(plaintext []byte) ([]byte, string) {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)

	pl := r.Intn(6) + 5
	sl := r.Intn(6) + 5

	plaintext = append(randomBytes(pl), plaintext...)
	plaintext = append(plaintext, randomBytes(sl)...)

	padded := pkcs7(plaintext, 16)
	key := randomAESKey()

	if r.Intn(2) == 0 {
		iv := randomBytes(16)
		return encryptAesCbc(padded, key, iv), "CBC"
	}
	return encryptAesEcbMultiblock(padded, key), "ECB"
}

func detectEncryption(ciphertext []byte) string {
	var reps int
	bs := 16

	for len(ciphertext) > 0 {
		reps += bytes.Count(ciphertext[bs:], ciphertext[:bs])
		ciphertext = ciphertext[bs:]
	}

	if reps == 0 {
		return "CBC"
	}
	return "ECB"
}
