package main

import (
  "fmt"
  "math"
  "strings"
  "io/ioutil"
  "encoding/hex"
)

func c4() {
  data, _ := ioutil.ReadFile("data/4.txt")
  output := "Now that the party is jumping\n"

  var bestPlaintext []byte
  var bestScore float64
  isSet := false

  for _, c := range strings.Split(string(data), "\n") {
    hex, _ := hex.DecodeString(c)
    for i := 0; i < 256; i++ {
      xored := single_byte_xor(hex, byte(i))
      score := score_english_string(xored)

      if !math.IsInf(score, 1) {
        if !isSet || score < bestScore {
          bestPlaintext = xored
          bestScore = score
          isSet = true
        }
      }
    }
  }

  if string(bestPlaintext) == output {
    fmt.Println("Challenge 4 passed!")
  } else {
    fmt.Println("Challenge 4 failed.")
  }
}
