package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

func c12() {
	output := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	decoded, _ := base64.StdEncoding.DecodeString(output)
	oracle := getOracle(decoded)
	plaintext, err := breakECB(oracle)
	if err == nil && bytes.Compare(plaintext, decoded) == 0 {
		fmt.Println("Challenge 12 passed!")
	} else {
		fmt.Println("Challenge 12 failed.")
	}
}
