package main

import (
  "fmt"
  "bytes"
  "io/ioutil"
  "encoding/hex"
)

func c8() {
  data, _ := ioutil.ReadFile("data/8.txt")
  output := 132
  inputs := bytes.Split(data, []byte{'\n'})

  ciphertexts := make([][]byte, 0, len(inputs))
  for _, val := range inputs {
    ciphertext := make([]byte, hex.DecodedLen(len(val)))
    hex.Decode(ciphertext, val)
    ciphertexts = append(ciphertexts, ciphertext)
  }

  scores := make([]int, len(ciphertexts))
  bs := 16
  for i, val := range ciphertexts {
    if len(val) % bs == 0 {
      var score int
      for len(val) > 0 {
        score += bytes.Count(val[bs:], val[:bs])
        val = val[bs:]
      }
      scores[i] = score
    } else {
      scores[i] = 0
    }
  }

  var answer int
  for i, val := range scores {
    if val > 0 {
      answer = i
    }
  }

  if answer == output {
    fmt.Println("Challenge 8 passed!")
  } else {
    fmt.Println("Challenge 8 failed.")
  }
}
