package playReady

import (
   "bytes"
   "encoding/hex"
   "io"
   "log"
   "net/http"
   "os"
   "testing"
)

var key_tests = []struct {
   key    string
   kid_wv string
   url    string
}{
   {
      key:    "ee0d569c019057569eaf28b988c206f6",
      kid_wv: "01038786b77fb6ca14eb864155de730e", // L1
      url:    "https://busy.prd.api.discomax.com/drm-proxy/any/drm-proxy/drm/license/play-ready?auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmF0aW9uVGltZSI6IjIwMjUtMDYtMThUMDY6NTQ6NTguNzIxMzMzMTc5WiIsImVkaXRJZCI6IjA2YTM4Mzk3LTg2MmQtNDQxOS1iZTg0LTA2NDE5Mzk4MjVlNyIsImFwcEJ1bmRsZSI6IiIsInBsYXRmb3JtIjoiIiwidXNlcklkIjoiVVNFUklEOmJvbHQ6MGQ0NWNjZjgtYjRhMi00MTQ3LWJiZWItYzdiY2IxNDBmMzgyIiwicHJvZmlsZUlkIjoiUFJPRklMRUlENGJlNDY5NDEtMDNhNS00N2U1LWI0MTQtZTlkOTVjMzlkMjE2IiwiZGV2aWNlSWQiOiIhIiwic3NhaSI6dHJ1ZSwic3RyZWFtVHlwZSI6InZvZCIsImhlYXJ0YmVhdEVuYWJsZWQiOmZhbHNlfQ.f2ptnQEXIcW3xNWDdlK1biJEMk5Sb4y-W_t5-UYqyeg",
   },
   {
      key:    "ab82952e8b567a2359393201e4dde4b4",
      kid_wv: "318f7ece69afcfe3e96de31be6b77272",
      url:    "https://prod-playready.rakuten.tv/v1/licensing/pr?uuid=bd497069-8a8f-40a8-b898-b5edf1327761",
   },
   {
      key:    "00000000000000000000000000000000",
      kid_wv: "10000000000000000000000000000000",
      url:    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:aescbc",
   },
}

func TestKey(t *testing.T) {
   data, err := os.ReadFile(SL2000.dir + "chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   var certificate Chain
   err = certificate.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + "signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   var signingKey EcKey
   signingKey.decode(data)
   data, err = os.ReadFile(SL2000.dir + "encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   var encryptKey EcKey
   encryptKey.decode(data)
   for _, test := range key_tests {
      log.Print(test.url)
      kid, err := hex.DecodeString(test.kid_wv)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(kid)
      data, err = certificate.requestBody(signingKey, kid)
      if err != nil {
         t.Fatal(err)
      }
      func() {
         resp, err := http.Post(test.url, "text/xml", bytes.NewReader(data))
         if err != nil {
            t.Fatal(err)
         }
         defer resp.Body.Close()
         data, err = io.ReadAll(resp.Body)
         if err != nil {
            t.Fatal(err)
         }
      }()
      var license1 license
      err = license1.decrypt(encryptKey, data)
      if err != nil {
         t.Fatal(err)
      }
      content := license1.contentKey
      UuidOrGuid(content.KeyID[:])
      if hex.EncodeToString(content.KeyID[:]) != test.kid_wv {
         t.Fatal(".KeyID")
      }
      if hex.EncodeToString(content.Key[:]) != test.key {
         t.Fatal(".Key")
      }
   }
}

var SL2000 = struct {
   dir string
   g1  string
   z1  string
}{
   dir: "ignore/",
   g1:  "g1",
   z1:  "z1",
}

func TestChain(t *testing.T) {
   data, err := os.ReadFile(SL2000.dir + SL2000.g1)
   if err != nil {
      t.Fatal(err)
   }
   var certificate Chain
   err = certificate.Decode(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + SL2000.z1)
   if err != nil {
      t.Fatal(err)
   }
   var z1 EcKey
   z1.decode(data)
   signingKey, err := Fill('S').key()
   if err != nil {
      t.Fatal(err)
   }
   encryptKey, err := Fill('E').key()
   if err != nil {
      t.Fatal(err)
   }
   err = certificate.CreateLeaf(&z1, signingKey, encryptKey)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"chain.txt", certificate.Encode())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"signing_key.txt", signingKey.Private())
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"encrypt_key.txt", encryptKey.Private())
   if err != nil {
      t.Fatal(err)
   }
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}
