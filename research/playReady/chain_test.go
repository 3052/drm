package playReady

import (
   "bytes"
   "encoding/hex"
   "encoding/json"
   "io"
   "net/http"
   "os"
   "testing"
)

var craveTests = []struct {
   keyID     string
   contentID string
   transform func([]byte) ([]byte, error)
   url       string
   expectKey string
}{
   {
      keyID:     "10000000000000000000000000000000",
      contentID: "",
      transform: func(payload []byte) ([]byte, error) { return payload, nil },
      url:       "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=ck:AAAAAAAAAAAAAAAAAAAAAA==,ckt:AES128BitCBC",
      expectKey: "00000000000000000000000000000000",
   },
   {
      keyID:     "3f962a1fb6aadb5cbc484df69dfda971",
      contentID: "ff-41f446bd-1474247",
      transform: func(payload []byte) ([]byte, error) {
         return json.Marshal(map[string]any{
            "payload": payload,
            "playbackContext": map[string]any{
               "contentId":        3300246,
               "contentpackageId": 8401705,
               "destinationId":    1880,
               "platformId":       1,
               "jwt":              "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2OTk2N2RhOWM5M2VlZjVkZjIwZjg3MTIiLCJzY29wZSI6ImFjY291bnQ6d3JpdGUgZGVmYXVsdCBtYXR1cml0eTphZHVsdCIsImlzcyI6Imh0dHBzOi8vYWNjb3VudC5iZWxsbWVkaWEuY2EiLCJjb250ZXh0Ijp7InByb2ZpbGVfaWQiOiI2OTk3MGVmYTczMTc2ZDJiMmU1M2E1YTMiLCJicmFuZF9pZHMiOlsiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTExIiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE0IiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE1Il19LCJleHAiOjE3NzUxOTE2NzksImlhdCI6MTc3NTE3NzI3OSwidmVyc2lvbiI6IlYyIiwianRpIjoiNzFiMDU5OWItNzY1Mi00NmM5LTg1ZjctYWYyYjc4NDgyNjE4IiwiYXV0aG9yaXRpZXMiOlsiUkVHVUxBUl9VU0VSIl0sImNsaWVudF9pZCI6ImNyYXZlLXdlYiJ9.tTyrslQVuSwvAF_GrjPptF730H7gmisP0djIYrGVzq-9FnHDjVFzfIy7YXpdBuXLfM4Y7-ElNDbDcpCEr_F0RCzzT3feMCBXIzvVO_sgUcbS-6oBsnMOTr6c6kEw41sCDa_79hFiNJzC1ak7lohvXjcTbpLXXzjMtzo5PSIQVzQyubgTQ02bub0778Ke5GZUFFP9jFBM7cDCKwI0wOxTuxnUOeIHasBcBp9Isp793DxCMIloVQ2qgR5l2QFjrt8T74KUryrJTMneXylWCLldBp7hvCLiA4YLklcYa0Cw024PMBy93Q9LKGY-HE-kmXUpiBT_MMB9xAqpSIwXaDRRcw",
            },
         })
      },
      url:       "https://license.9c9media.com/playready",
      expectKey: "13207ee81394da90b6451e9ec0e917a7",
   },
}

func TestCrave(t *testing.T) {
   paths := getPaths("ignore/SL3000")
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

   for _, tc := range craveTests {
      kid, err := hex.DecodeString(tc.keyID)
      if err != nil {
         t.Fatal(err)
      }
      UuidOrGuid(kid)
      payload, err := chain_data.LicenseRequestBytes(signingKey, kid, tc.contentID)
      if err != nil {
         t.Fatal(err)
      }
      reqData, err := tc.transform(payload)
      if err != nil {
         t.Fatal(err)
      }

      req, err := http.NewRequest("POST", tc.url, bytes.NewReader(reqData))
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

         licenseData, err := ParseLicense(respData)
         if err != nil {
            t.Fatal(err)
         }

         key, err := licenseData.Decrypt(encryptKey)
         if err != nil {
            t.Fatal(err)
         }

         keyHex := hex.EncodeToString(key)
         if keyHex != tc.expectKey {
            t.Fatalf("expected key %s, got %s", tc.expectKey, keyHex)
         }
         t.Logf("Successfully retrieved expected key: %x", key)
      }()
   }
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
