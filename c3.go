package main

import (
  "fmt"
  "encoding/hex"
)

func c3() {
  input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  output := "Cooking MC's like a pound of bacon"
  hex, _ := hex.DecodeString(input)

  minKey := breakSingleKeyXor(hex)

  if string(single_byte_xor(hex, minKey)) == output {
    fmt.Println("Challenge 3 passed!")
  } else {
    fmt.Println("Challenge 3 failed.")
  }
}
