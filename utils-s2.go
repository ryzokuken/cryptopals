package main

import (
	"bytes"
	"crypto/aes"
	"errors"
	"math/rand"
	"time"
)

func breakECB(oracle func([]byte, []byte) []byte) ([]byte, error) {
	// Step 1: Generate a Random Key
	rk := randomAESKey()

	// Step 2: Find the blocksize
	first := len(oracle([]byte{'A'}, rk))
	buffer := []byte{'A', 'A'}
	var bs int
	for len(buffer) < 100 {
		enc := oracle(buffer, rk)
		if len(enc) != first {
			bs = len(enc) - first
			break
		}
		buffer = append(buffer, byte('A'))
	}
	if bs != 16 {
		return nil, errors.New("Something went wrong.")
	}

	// Step 3: Detect ECB
	if detectEncryption(oracle(message, rk)) != "ECB" {
		return nil, errors.New("Something went wrong.")
	}

	// Step 4: Find the plaintext
	byteOffset := 0
	maxOffset := len(oracle([]byte{}, rk)) / bs
	var answer []byte
	for byteOffset < maxOffset {
		block := make([]byte, bs-1)
		for i := range block {
			block[i] = byte('A')
		}
		input := append(block, answer...)
		for true {
			enc := oracle(block, rk)
			found := false
			empty := false
			for i := 0; i < 256; i++ {
				ip := append(input, byte(i))
				ec := oracle(ip, rk)
				if bytes.Compare(enc[bs*byteOffset:bs*(byteOffset+1)], ec[bs*byteOffset:bs*(byteOffset+1)]) == 0 {
					found = true
					result := ip[len(ip)-1]
					if result == 1 {
						return answer, nil
					}
					answer = append(answer, result)
					if len(block) > 0 {
						block = block[1:]
					} else {
						empty = true
					}
					input = append(input, result)[1:]
					break
				}
			}
			if !found {
				panic("Could not find a possible value")
			}
			if empty {
				byteOffset++
				break
			}
		}
	}
	return nil, errors.New("Something went wrong.")
}

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

func encryptAesEcb(plaintext, key []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	bs := block.BlockSize()

	if len(plaintext) != bs {
		return nil, errors.New("Should be a multiple of blocksize")
	}

	ciphertext := make([]byte, bs)
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
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

		encryption, _ := encryptAesEcb(fixedXor(pb, buffer), key)
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

func encryptAesEcbMultiblock(plaintext, key []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	bs := block.BlockSize()

	if len(plaintext)%bs != 0 {
		return nil, errors.New("Must be a mutiple of the blocksize")
	}

	ciphertext := make([]byte, 0, len(plaintext))
	for len(plaintext) > 0 {
		cb := make([]byte, bs)
		block.Encrypt(cb, plaintext)
		plaintext = plaintext[bs:]
		ciphertext = append(ciphertext, cb...)
	}

	return ciphertext, nil
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
	e, _ := encryptAesEcbMultiblock(padded, key)
	return e, "ECB"
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

func getOracle(unknown []byte) func([]byte, []byte) []byte {
	return func(p, k []byte) []byte {
		p = append(p, unknown...)
		p = pkcs7(p, 16)
		e, _ := encryptAesEcbMultiblock(p, k)
		return e
	}
}
