package main

import (
   "41.neocities.org/drm/playReady"
   "flag"
   "log"
   "math/big"
   "os"
)

func (c *command) do_g1_z1() error {
   // g1
   data, err := os.ReadFile(c.g1)
   if err != nil {
      return err
   }
   var certificate playReady.Chain
   err = certificate.Decode(data)
   if err != nil {
      return err
   }
   err = write_file("CertificateChain", certificate.Encode())
   if err != nil {
      return err
   }
   // z1
   data, err = os.ReadFile(c.z1)
   if err != nil {
      return err
   }
   z1 := new(big.Int).SetBytes(data)
   encrypt_sign_key := big.NewInt(c.encrypt_sign)
   err = certificate.Leaf(z1, encrypt_sign_key)
   if err != nil {
      return err
   }
   return write_file("EncryptSignKey", encrypt_sign_key.Bytes())
}

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
   flag.Int64Var(&c.encrypt_sign, "e", 1, "encrypt/sign")
   flag.StringVar(&c.g1, "g", "", "g1")
   flag.StringVar(&c.z1, "z", "", "z1")
   flag.Parse()
   if c.g1 != "" {
      if c.z1 != "" {
         return c.do_g1_z1()
      }
   }
   flag.Usage()
   return nil
}

type command struct {
   encrypt_sign int64
   g1           string
   z1           string
}
