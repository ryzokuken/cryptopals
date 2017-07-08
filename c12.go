package main

import (
	"encoding/base64"
	"bytes"
	"fmt"
)

func c12() {
	output := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

	// Step 1: Generate a Random Key
	rk := randomAESKey()

	// Step 2: Find the blocksize
	first := len(byteAtATimeECBDecryption([]byte{'A'}, rk))
	buffer := []byte{'A', 'A'}
	var bs int
	for len(buffer) < 100 {
		enc := byteAtATimeECBDecryption(buffer, rk)
		if len(enc) != first {
			bs = len(enc) - first
			break
		}
		buffer = append(buffer, byte('A'))
	}
	if bs != 16 {
		fmt.Println("Challenge 12 failed.")
		return
	}

	// Step 3: Detect ECB
	if detectEncryption(byteAtATimeECBDecryption(message, rk)) != "ECB" {
		fmt.Println("Challenge 12 failed.")
		return
	}

	// Step 4: Find the plaintext
	byteOffset := 0
	maxOffset := len(byteAtATimeECBDecryption([]byte{}, rk)) / bs
	var answer []byte
	for byteOffset < maxOffset {
		block := make([]byte, bs-1)
		for i := range block {
			block[i] = byte('A')
		}
		input := append(block, answer...)
		for true {
			enc := byteAtATimeECBDecryption(block, rk)
			found := false
			empty := false
			for i := 0; i < 256; i++ {
				ip := append(input, byte(i))
				ec := byteAtATimeECBDecryption(ip, rk)
				if bytes.Compare(enc[bs*byteOffset:bs*(byteOffset+1)], ec[bs*byteOffset:bs*(byteOffset+1)]) == 0 {
					found = true
					result := ip[len(ip)-1]
					if result == 1 {
						expected, _ := base64.StdEncoding.DecodeString(output)
						if bytes.Compare(answer, expected) == 0 {
							fmt.Println("Challenge 12 passed!")
						} else {
							fmt.Println("Challenge 12 failed.")
						}
						return
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

	fmt.Println("Challenge 12 failed.")
	return
}
