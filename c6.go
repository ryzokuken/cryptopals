package main

import (
  "fmt"
  "bytes"
  "io/ioutil"
  "encoding/base64"

  // "github.com/steakknife/hamming"
)

func c6() {
  data, _ := ioutil.ReadFile("data/6.txt")
  output := "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \nn"

  input := bytes.Replace(data, []byte{'\n'}, nil, -1);
  decoded := make([]byte, base64.StdEncoding.DecodedLen(len(input)))
  base64.StdEncoding.Decode(decoded, input)

  plaintext := make([]byte, len(decoded))
  copy(plaintext, decoded)

  // scores := make([]int, 39)
  // for i := 2; i <= 40; i++ {
  //   scores[i - 2] += hamming.Bytes(decoded[0:i], decoded[i:2*i]) / i
  // }
  // for i := 2; i <= 40; i++ {
  //   scores[i - 2] += (
  //     hamming.Bytes(decoded[0:i], decoded[i:2*i]) +
  //     hamming.Bytes(decoded[0:i], decoded[2*i:3*i]) +
  //     hamming.Bytes(decoded[i:2*i], decoded[2*i:3*i])) / (i * 3)
  // }
  // for i := 2; i <= 40; i++ {
  //   scores[i - 2] += (
  //     hamming.Bytes(decoded[0:i], decoded[i:2*i]) +
  //     hamming.Bytes(decoded[0:i], decoded[2*i:3*i]) +
  //     hamming.Bytes(decoded[0:i], decoded[3*i:4*i]) +
  //     hamming.Bytes(decoded[i:2*i], decoded[2*i:3*i]) +
  //     hamming.Bytes(decoded[i:2*i], decoded[3*i:4*i]) +
  //     hamming.Bytes(decoded[2*i:3*i], decoded[3*i:4*i])) / (i * 6)
  // }
  // for i := 2; i <= 40; i++ {
  //   scores[i - 2] += (
  //     hamming.Bytes(decoded[0:i], decoded[i:2*i]) +
  //     hamming.Bytes(decoded[0:i], decoded[2*i:3*i]) +
  //     hamming.Bytes(decoded[0:i], decoded[3*i:4*i]) +
  //     hamming.Bytes(decoded[0:i], decoded[4*i:5*i]) +
  //     hamming.Bytes(decoded[i:2*i], decoded[2*i:3*i]) +
  //     hamming.Bytes(decoded[i:2*i], decoded[3*i:4*i]) +
  //     hamming.Bytes(decoded[i:2*i], decoded[4*i:5*i]) +
  //     hamming.Bytes(decoded[2*i:3*i], decoded[3*i:4*i]) +
  //     hamming.Bytes(decoded[2*i:3*i], decoded[4*i:5*i]) +
  //     hamming.Bytes(decoded[3*i:4*i], decoded[4*i:5*i])) / (i * 6)
  // }

  keylength := 29
  nsplit := len(decoded) / 29
  blocks := make([][]byte, 0, nsplit + 1)

  for i := 0; i < nsplit; i++ {
    blocks = append(blocks, decoded[:keylength])
    decoded = decoded[keylength:]
  }
  if len(decoded) > 0 {
    blocks = append(blocks, decoded)
  }

  transpose := make([][]byte, 29)
  for i := range transpose {
    row := make([]byte, 0, nsplit + 1)
    for _, block := range blocks {
      if i < len(block) {
        row = append(row, block[i])
      }
    }
    transpose[i] = row
  }

  key := make([]byte, 29)
  for i := range key {
    key[i] = breakSingleKeyXor(transpose[i])
  }

  if string(repeatingKeyXor(plaintext, key)) == output {
    fmt.Println("Challenge 6 passed!")
  } else {
    fmt.Println("Challenge 6 failed.")
  }
}
