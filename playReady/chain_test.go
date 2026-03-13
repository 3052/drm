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

func TestChain(t *testing.T) {
   data, err := os.ReadFile(SL2000.dir + SL2000.g1)
   if err != nil {
      t.Fatal(err)
   }
   certificate, err := DecodeChain(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + SL2000.z1)
   if err != nil {
      t.Fatal(err)
   }
   z1, err := DecodeEcKey(data)
   if err != nil {
      t.Fatal(err)
   }

   signingKey, err := GenerateEcKey()
   if err != nil {
      t.Fatal(err)
   }

   encryptKey, err := GenerateEcKey()
   if err != nil {
      t.Fatal(err)
   }

   err = certificate.CreateLeaf(z1, signingKey, encryptKey)
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"/chain.txt", certificate.Encode())
   if err != nil {
      t.Fatal(err)
   }
   data, err = encryptKey.Private()
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"/encrypt_key.txt", data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = signingKey.Private()
   if err != nil {
      t.Fatal(err)
   }
   err = write_file(SL2000.dir+"/signing_key.txt", data)
   if err != nil {
      t.Fatal(err)
   }
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

var SL2000 = struct {
   dir string
   g1  string
   z1  string
}{
   dir: "ignore/SL2000",
   g1:  "/bgroupcert.dat",
   z1:  "/zgpriv.dat",
}

var key_tests = []struct {
   key    string
   kid_wv string
   url    string
}{
   {
      key:    "00000000000000000000000000000000",
      kid_wv: "10000000000000000000000000000000",
      url:    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==",
   },
   {
      key:    "00000000000000000000000000000000",
      kid_wv: "10000000000000000000000000000000",
      url:    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:AES128BitCBC",
   },
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
}[:2]

func TestKey(t *testing.T) {
   data, err := os.ReadFile(SL2000.dir + "/chain.txt")
   if err != nil {
      t.Fatal(err)
   }
   certificate, err := DecodeChain(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + "/signing_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   signingKey, err := DecodeEcKey(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(SL2000.dir + "/encrypt_key.txt")
   if err != nil {
      t.Fatal(err)
   }
   encryptKey, err := DecodeEcKey(data)
   if err != nil {
      t.Fatal(err)
   }
   for _, test := range key_tests {
      log.Print(test.url)
      kid, err := hex.DecodeString(test.kid_wv)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(kid)
      // Calls generated exported function
      data, err = certificate.GenerateLicenseRequest(signingKey, kid)
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
      // Calls exported method on EcKey
      licenseData, err := encryptKey.DecryptLicense(data)
      if err != nil {
         t.Fatal(err)
      }
      // Accesses exported field
      content := licenseData.ContentKey
      UuidOrGuid(content.KeyID[:])
      if hex.EncodeToString(content.KeyID[:]) != test.kid_wv {
         t.Fatal(".KeyID")
      }
      if hex.EncodeToString(content.Key[:]) != test.key {
         t.Fatal(".Key")
      }
   }
}
