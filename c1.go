package main

import (
  "fmt"
  "encoding/hex"
  "encoding/base64"
)

func c1() {
  input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
  output := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

  hex, _ := hex.DecodeString(input)
  result := base64.StdEncoding.EncodeToString(hex)

  if result == output {
    fmt.Println("Challenge 1 passed!")
  } else {
    fmt.Println("Challenge 1 failed.")
  }
}
