package main

import (
	"bytes"
	"fmt"
)

func c12() {
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
	fmt.Println(bs)

	// Step 3: Detect ECB
	fmt.Println(detectEncryption(byteAtATimeECBDecryption(message, rk)))

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
		// fmt.Printf("%d %d\n", byteOffset * bs, len(input))
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
						return
					}
					fmt.Print(string(i))
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
}
