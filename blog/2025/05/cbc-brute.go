package main

import (
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "fmt"
   "iter"
   "log"
   "os"
)

const (
   stage0 = "MSTAR_SECURE_STORE_FILE_MAGIC_ID"
   stage1 = "INNER_MSTAR_FILE"
)

func get_source(data []byte) iter.Seq[[]byte] {
   magic_id := bytes.Index(data, []byte(stage0))
   return func(yield func([]byte) bool) {
      for i := 0; i < magic_id; i++ {
         if len(data[i:])%16 == 0 {
            log.Println("source", i)
            if !yield(data[i:]) {
               return
            }
         }
      }
   }
}

func get_key(data []byte) iter.Seq[[]byte] {
   return func(yield func([]byte) bool) {
      for len(data) >= 16 {
         if !yield(data[:16]) {
            return
         }
         data = data[1:]
      }
   }
}

func main() {
   sources, err := os.ReadFile("zgpriv_protected.dat")
   if err != nil {
      panic(err)
   }
   keys, err := os.ReadFile("MBOOT.bin")
   if err != nil {
      panic(err)
   }
   var iv [16]byte
   dest := make([]byte, len(sources))
   for source := range get_source(sources) {
      for key := range get_key(keys) {
         block, err := aes.NewCipher(key)
         if err != nil {
            panic(err)
         }
         cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(dest, source)
         if bytes.Contains(dest, []byte(stage1)) {
            fmt.Println("pass")
            return
         }
      }
   }
   fmt.Println("fail")
}
