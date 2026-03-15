package main

import (
   "41.neocities.org/drm/playReady"
   "bytes"
   "encoding/hex"
   "log"
   "net/http"
   "os"
)

var paths = struct {
   groupCert, zPriv, devCert, zPrivEncr, zPrivSig string
}{
   devCert:   "/SL2000/bdevcert.dat",
   zPrivSig:  "/SL2000/zprivsig.dat",
}

func main() {
   cache, err := os.UserCacheDir()
   if err != nil {
      panic(err)
   }
   data, err := os.ReadFile(cache + paths.devCert)
   if err != nil {
      panic(err)
   }
   certificate, err := playReady.ParseChain(data)
   if err != nil {
      panic(err)
   }
   data, err = os.ReadFile(cache + paths.zPrivSig)
   if err != nil {
      panic(err)
   }
   signingKey, err := playReady.ParseRawPrivateKey(data)
   if err != nil {
      panic(err)
   }
   kid, err := hex.DecodeString("10000000000000000000000000000000")
   if err != nil {
      panic(err)
   }
   playReady.UuidOrGuid(kid)
   data, err = certificate.LicenseRequestBytes(signingKey, kid)
   if err != nil {
      panic(err)
   }
   req, err := http.NewRequest(
      "POST",
      //pass
      //"https://playready.larley.dev/RightsManager/ClientInfo",
      //fail
      "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(msg:clientinfo)",
      bytes.NewReader(data),
   )
   if err != nil {
      panic(err)
   }
   req.Header.Set("content-type", "text/xml")
   log.Println(req.Method, req.URL)
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      panic(err)
   }
   defer resp.Body.Close()
   err = resp.Write(os.Stdout)
   if err != nil {
      panic(err)
   }
}
