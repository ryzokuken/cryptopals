package main

import (
  "fmt"
  "encoding/hex"
)

func c2() {
  input1 := "1c0111001f010100061a024b53535009181c"
  input2 := "686974207468652062756c6c277320657965"
  output := "746865206b696420646f6e277420706c6179"

  hex1, _ := hex.DecodeString(input1)
  hex2, _ := hex.DecodeString(input2)

  result := hex.EncodeToString(fixed_xor(hex1, hex2))

  if result == output {
    fmt.Println("Challenge 2 passed!")
  } else {
    fmt.Println("Challenge 2 failed.")
  }
}
