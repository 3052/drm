package playReady

import (
   "bytes"
   "encoding/hex"
   "encoding/json"
   "io"
   "log"
   "net/http"
   "os"
   "testing"
)

func TestKey(t *testing.T) {
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
   encrypt_key, err := ParseRawPrivateKey(data)
   if err != nil {
      t.Fatal(err)
   }
   for _, test := range key_tests {
      kid, err := hex.DecodeString(test.key_id)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(kid)
      payload, err := chain_data.LicenseRequestBytes(
         signingKey, kid, test.content_id,
      )
      if err != nil {
         t.Fatal(err)
      }
      reqData, err := test.transform(payload)
      if err != nil {
         t.Fatal(err)
      }

      req, err := http.NewRequest("POST", test.url, bytes.NewReader(reqData))
      if err != nil {
         t.Fatal(err)
      }
      t.Log(req.URL)

      // Scope the defer strictly to the response lifecycle
      func() {
         resp, err := http.DefaultClient.Do(req)
         if err != nil {
            t.Fatal(err)
         }
         defer resp.Body.Close()

         respData, err := io.ReadAll(resp.Body)
         if err != nil {
            t.Fatal(err)
         }
         if resp.StatusCode != http.StatusOK {
            t.Fatalf("StatusCode %v respData %q", resp.StatusCode, string(respData))
         }
         license_data, err := ParseLicense(respData)
         if err != nil {
            t.Fatal(err)
         }
         // key
         key, err := license_data.Decrypt(encrypt_key)
         if err != nil {
            t.Fatal(err)
         }
         if hex.EncodeToString(key) != test.key {
            t.Fatal("key")
         }
         // key ID DO THIS AFTER KEY
         UuidOrGuid(
            license_data.ContainerOuter.ContainerKeys.ContentKey.GuidKeyID,
         )
         key_id := hex.EncodeToString(
            license_data.ContainerOuter.ContainerKeys.ContentKey.GuidKeyID,
         )
         if key_id != test.key_id {
            t.Fatal("key ID")
         }
      }()
   }
}

var key_tests = []struct {
   content_id string
   key        string
   key_id     string
   transform  func([]byte) ([]byte, error)
   url        string
}{
   {
      key_id:     "10000000000000000000000000000000",
      content_id: "",
      transform:  func(payload []byte) ([]byte, error) { return payload, nil },
      url:        "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:AES128BitCBC",
      key:        "00000000000000000000000000000000",
   },
   {
      key_id:     "3f962a1fb6aadb5cbc484df69dfda971",
      content_id: "ff-41f446bd-1474247",
      transform: func(payload []byte) ([]byte, error) {
         return json.Marshal(map[string]any{
            "payload": payload,
            "playbackContext": map[string]any{
               "contentId":        3300246,
               "contentpackageId": 8401705,
               "destinationId":    1880,
               "platformId":       1,
               "jwt":              "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2OTk2N2RhOWM5M2VlZjVkZjIwZjg3MTIiLCJzY29wZSI6ImFjY291bnQ6d3JpdGUgZGVmYXVsdCBtYXR1cml0eTphZHVsdCIsImlzcyI6Imh0dHBzOi8vYWNjb3VudC5iZWxsbWVkaWEuY2EiLCJjb250ZXh0Ijp7InByb2ZpbGVfaWQiOiI2OTk3MGVmYTczMTc2ZDJiMmU1M2E1YTMiLCJicmFuZF9pZHMiOlsiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTExIiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE0IiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE1Il19LCJleHAiOjE3NzUyNjI2NzEsImlhdCI6MTc3NTI0ODI3MSwidmVyc2lvbiI6IlYyIiwianRpIjoiN2QzOWRhNjUtYjAwOS00N2JjLTk3YzgtYzM2NmQyYTI5ODRlIiwiYXV0aG9yaXRpZXMiOlsiUkVHVUxBUl9VU0VSIl0sImNsaWVudF9pZCI6ImNyYXZlLXdlYiJ9.a3HdZEJhHaal36Ii1M11VlsTBTkubo1NRFlIF9sBdKpyiqNBDFDofJ4132gLs4oqHnaRLZ_JuJzJOxaBECvIvnrymXWxEe7CtUHloAYtnPv_ZAHjvmI65999n3L9NIMgUD08oJ9WLGyjMc-h75EAFieLBayYmz_NGFt7kiun9xAKwj3d-jBj5GwLvvAbBn867Gbx3YIfJzHDgtJFFGKp9ZNaKUB9xIwbm7OUgP7iulVKCZwN11UpopDRtho9gB-fQUybUzGQuqb-pmh-iyA_sxyEtL2KnfANC5ueSPnrJf77uTluhfGnH0w21tlIvjNHrgrXEKE9oJGrvoZDgNbO2w",
            },
         })
      },
      url: "https://license.9c9media.com/playready",
      key: "13207ee81394da90b6451e9ec0e917a7",
   },
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
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
      encrypt_key, err := GenerateKey()
      if err != nil {
         t.Fatal(err)
      }
      err = chain_data.GenerateLeaf(modelKey, signingKey, encrypt_key)
      if err != nil {
         t.Fatal(err)
      }
      err = write_file(paths.devCert, chain_data.Bytes())
      if err != nil {
         t.Fatal(err)
      }
      data, err = PrivateKeyBytes(encrypt_key)
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
   }
}
