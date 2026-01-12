package main

import (
   "41.neocities.org/drm/playReady"
   "flag"
   "fmt"
   "log"
   "math/big"
   "os"
)

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

func main() {
   log.SetFlags(log.Ltime)
   err := new(command).run()
   if err != nil {
      log.Fatal(err)
   }
}

func (c *command) run() error {
   // 1
   flag.Int64Var(&c.set_encrypt_sign, "e", 1, "set encrypt/sign")
   flag.StringVar(&c.g1, "g", "", "g1")
   flag.StringVar(&c.z1, "z", "", "z1")
   // 2
   flag.StringVar(&c.get_encrypt_sign, "k", "", "get encrypt/sign")
   flag.Parse()
   // 1
   if c.g1 != "" {
      if c.z1 != "" {
         return c.do_g1_z1()
      }
   }
   // 2
   if c.get_encrypt_sign != "" {
      return c.do_get_encrypt_sign()
   }
   flag.Usage()
   return nil
}

func (c *command) do_g1_z1() error {
   // z1
   data, err := os.ReadFile(c.z1)
   if err != nil {
      return err
   }
   z1 := new(big.Int).SetBytes(data)
   encrypt_sign_key := big.NewInt(c.set_encrypt_sign)
   err = write_file("EncryptSignKey", encrypt_sign_key.Bytes())
   if err != nil {
      return err
   }
   // g1
   data, err = os.ReadFile(c.g1)
   if err != nil {
      return err
   }
   var certificate playReady.Chain
   err = certificate.Decode(data)
   if err != nil {
      return err
   }
   err = certificate.Leaf(z1, encrypt_sign_key)
   if err != nil {
      return err
   }
   return write_file("CertificateChain", certificate.Encode())
}

type command struct {
   // 1
   g1               string
   z1               string
   set_encrypt_sign int64
   // 2
   get_encrypt_sign string
}

func (c *command) do_get_encrypt_sign() error {
   data, err := os.ReadFile(c.get_encrypt_sign)
   if err != nil {
      return err
   }
   // Convert bytes back to Big Int
   key := new(big.Int).SetBytes(data)
   // Print the integer value (Decimal)
   fmt.Println(key)
   return nil
}
