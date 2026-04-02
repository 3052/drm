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

func TestKey(t *testing.T) {
   // Only test SL2000 for network/license retrieval
   paths := getPaths("ignore/SL2000")

   data, err := os.ReadFile(paths.devCert)
   if err != nil {
      t.Fatal(err)
   }
   chain_data, err := ParseChain(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(paths.zPrivSig)
   if err != nil {
      t.Fatal(err)
   }
   signingKey, err := ParseRawPrivateKey(data)
   if err != nil {
      t.Fatal(err)
   }
   data, err = os.ReadFile(paths.zPrivEncr)
   if err != nil {
      t.Fatal(err)
   }
   encryptKey, err := ParseRawPrivateKey(data)
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
      data, err = chain_data.LicenseRequestBytes(signingKey, kid, "")
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
      licenseData, err := ParseLicense(data)
      if err != nil {
         t.Fatal(err)
      }
      key, err := licenseData.Decrypt(encryptKey)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(
         licenseData.ContainerOuter.ContainerKeys.ContentKey.GuidKeyID,
      )
      key_id := hex.EncodeToString(
         licenseData.ContainerOuter.ContainerKeys.ContentKey.GuidKeyID,
      )
      if key_id != test.kid_wv {
         t.Fatal(".KeyID")
      }
      if hex.EncodeToString(key) != test.key {
         t.Fatal(".Key")
      }
   }
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

var key_tests = []struct {
   key    string
   kid_wv string
   url    string
}{
   {
      key:    "00000000000000000000000000000000",
      kid_wv: "10000000000000000000000000000000",
      url:    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==", // AES128BitCTR
   },
   {
      key:    "00000000000000000000000000000000",
      kid_wv: "10000000000000000000000000000000",
      url:    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:AES128BitCBC",
   },
}
type testPaths struct {
   groupCert string
   zPriv     string
   devCert   string
   zPrivEncr string
   zPrivSig  string
}

func getPaths(baseDir string) testPaths {
   return testPaths{
      groupCert: baseDir + "/bgroupcert.dat",
      zPriv:     baseDir + "/zgpriv.dat",
      devCert:   baseDir + "/bdevcert.dat",
      zPrivEncr: baseDir + "/zprivencr.dat",
      zPrivSig:  baseDir + "/zprivsig.dat",
   }
}

func TestChain(t *testing.T) {
   directories := []string{"ignore/SL2000", "ignore/SL3000"}

   for _, baseDir := range directories {
      t.Run(baseDir, func(t *testing.T) {
         paths := getPaths(baseDir)

         data, err := os.ReadFile(paths.groupCert)
         if err != nil {
            t.Fatal(err)
         }
         chain_data, err := ParseChain(data)
         if err != nil {
            t.Fatal(err)
         }
         data, err = os.ReadFile(paths.zPriv)
         if err != nil {
            t.Fatal(err)
         }
         modelKey, err := ParseRawPrivateKey(data)
         if err != nil {
            t.Fatal(err)
         }
         signingKey, err := GenerateKey()
         if err != nil {
            t.Fatal(err)
         }
         encryptKey, err := GenerateKey()
         if err != nil {
            t.Fatal(err)
         }
         err = chain_data.GenerateLeaf(modelKey, signingKey, encryptKey)
         if err != nil {
            t.Fatal(err)
         }
         err = write_file(paths.devCert, chain_data.Bytes())
         if err != nil {
            t.Fatal(err)
         }
         data, err = PrivateKeyBytes(encryptKey)
         if err != nil {
            t.Fatal(err)
         }
         err = write_file(paths.zPrivEncr, data)
         if err != nil {
            t.Fatal(err)
         }
         data, err = PrivateKeyBytes(signingKey)
         if err != nil {
            t.Fatal(err)
         }
         err = write_file(paths.zPrivSig, data)
         if err != nil {
            t.Fatal(err)
         }
      })
   }
}
