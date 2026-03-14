package main

import (
   "41.neocities.org/drm/playReady"
   "flag"
   "fmt"
   "log"
   "os"
)

func (c *client) do_certificate_key() error {
   data, err := os.ReadFile(c.certificate)
   if err != nil {
      return err
   }
   certificate, err := playReady.ParseChain(data)
   if err != nil {
      return err
   }
   data, err = os.ReadFile(c.key)
   if err != nil {
      return err
   }
   modelKey, err := playReady.ParseRawPrivateKey(data)
   if err != nil {
      return err
   }
   signingKey, err := playReady.GenerateKey()
   if err != nil {
      return err
   }
   encryptKey, err := playReady.GenerateKey()
   if err != nil {
      return err
   }
   err = certificate.GenerateLeaf(modelKey, signingKey, encryptKey)
   if err != nil {
      return err
   }
   err = write_file("bdevcert.dat", certificate.Bytes())
   if err != nil {
      return err
   }
   data, err = playReady.PrivateKeyBytes(encryptKey)
   if err != nil {
      return err
   }
   err = write_file("zprivencr.dat", data)
   if err != nil {
      return err
   }
   data, err = playReady.PrivateKeyBytes(signingKey)
   if err != nil {
      return err
   }
   return write_file("zprivsig.dat", data)
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

func main() {
   log.SetFlags(log.Ltime)
   err := new(client).do()
   if err != nil {
      log.Fatal(err)
   }
}

func (c *client) do() error {
   // 1
   flag.StringVar(&c.certificate, "c", "", "certificate")
   // 2
   flag.StringVar(&c.key, "k", "", "key")
   flag.Parse()
   if c.certificate != "" {
      // 2
      if c.key != "" {
         return c.do_certificate_key()
      }
      // 1
      return c.do_certificate()
   }
   flag.Usage()
   return nil
}

func (c *client) do_certificate() error {
   data, err := os.ReadFile(c.certificate)
   if err != nil {
      return err
   }
   chain, err := playReady.ParseChain(data)
   if err != nil {
      return err
   }
   for _, certificate := range chain.Certs {
      fmt.Printf("%+v\n", certificate.ManufacturerInfo)
   }
   return nil
}

type client struct {
   // 1
   certificate string
   // 2
   key string
}
