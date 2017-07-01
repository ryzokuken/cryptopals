package main

import "fmt"

func c9() {
  input := "YELLOW SUBMARINE"
  bs := 20
  output := []byte(input)
  for i := 0; i < 4; i++ {
    output = append(output, byte(4))
  }
  if string(pkcs7([]byte(input), bs)) == string(output) {
    fmt.Println("Challenge 9 passed!")
  } else {
    fmt.Println("Challenge 9 failed.")
  }
}
