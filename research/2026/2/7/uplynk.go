package main

import (
   "41.neocities.org/drm/playReady"
   "41.neocities.org/drm/playReady/xml"
   "bytes"
   "encoding/hex"
   "fmt"
   "io"
   "math/big"
   "net/http"
   "net/url"
   "os"
)

func main() {
   data, err := os.ReadFile("CertificateChain")
   if err != nil {
      panic(err)
   }
   var chain playReady.Chain
   err = chain.Decode(data)
   if err != nil {
      panic(err)
   }
   data, err = os.ReadFile("EncryptSignKey")
   if err != nil {
      panic(err)
   }
   encrypt_sign_key := new(big.Int).SetBytes(data)
   kid, err := hex.DecodeString(kid_uuid)
   if err != nil {
      panic(err)
   }
   playReady.UuidOrGuid(kid)
   header := xml.WrmHeaderData{
      ProtectInfo: xml.ProtectInfo{
         KeyLen: "16",
         AlgId:  "AESCTR",
      },
      Kid: kid,
   }
   data, err = chain.RequestBody(&header, encrypt_sign_key)
   if err != nil {
      panic(err)
   }
   var req http.Request
   req.Header = http.Header{}
   req.Method = "POST"
   req.URL = &url.URL{}
   req.URL.Scheme = "https"
   req.Body = io.NopCloser(bytes.NewReader(data))
   req.Header.Set("content-type", "text/xml")
   req.URL.Host = "content.uplynk.com"
   req.URL.Path = "/pr"
   resp, err := http.DefaultClient.Do(&req)
   if err != nil {
      panic(err)
   }
   defer resp.Body.Close()
   data, err = io.ReadAll(resp.Body)
   if err != nil {
      panic(err)
   }
   if resp.StatusCode != http.StatusOK {
      panic(string(data))
   }
   var license playReady.License
   coord, err := license.Decrypt(data, encrypt_sign_key)
   if err != nil {
      panic(err)
   }
   playReady.UuidOrGuid(license.ContentKey.KeyId[:])
   if hex.EncodeToString(license.ContentKey.KeyId[:]) != kid_uuid {
      panic(".KeyId")
   }
   fmt.Println(hex.EncodeToString(coord.Key()))
}

const kid_uuid = "85877dfc046947328b273987bf8d5bb8"
