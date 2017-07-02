package main

import (
  "crypto/aes"
)

func pkcs7(message []byte, bs int) []byte {
  if len(message) % bs == 0 {
    result := make([]byte, 0, len(message) + bs)
    for _, b := range message {
      result = append(result, b)
    }
    for i := 0; i < bs; i++ {
      result = append(result, byte(bs))
    }
    return result
  } else {
    residue := bs - (len(message) % bs)
    result := make([]byte, 0, len(message) + residue)
    for _, b := range message {
      result = append(result, b)
    }
    for i := 0; i < residue; i++ {
      result = append(result, byte(residue))
    }
    return result
  }
}

func encryptAesEcb(plaintext, key []byte) []byte {
  block, _ := aes.NewCipher(key)
  bs := block.BlockSize()

  if len(plaintext) != bs {
    panic("Need a multiple of the blocksize")
  }

  ciphertext := make([]byte, bs)
  block.Encrypt(ciphertext, plaintext)
  return ciphertext
}

func decryptAesEcb(ciphertext, key []byte) []byte {
  block, _ := aes.NewCipher(key)
  bs := block.BlockSize()

  if len(ciphertext) != bs {
    panic("Need a multiple of the blocksize")
  }

  plaintext := make([]byte, bs)
  block.Decrypt(plaintext, ciphertext)
  return plaintext
}

func decryptAesCbc(ciphertext, key, iv []byte) []byte {
  bs := len(key)
  if len(ciphertext) % bs != 0 {
    panic("Need a multiple of the blocksize")
  }

  plaintext := make([]byte, 0, len(ciphertext))
  buffer := make([]byte, bs)
  copy(buffer, iv)
  for len(ciphertext) > 0 {
    cb := ciphertext[:bs]
    ciphertext = ciphertext[bs:]

    decryption := decryptAesEcb(cb, key)
    plaintext = append(plaintext, fixed_xor(decryption, buffer)...)
    buffer = cb
  }

  return plaintext
}
