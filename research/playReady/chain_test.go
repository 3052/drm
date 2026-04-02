package playReady

import (
   "bytes"
   "encoding/base64"
   "encoding/json"
   "io"
   "net/http"
   "os"
   "testing"
)

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
   kid, err := base64.StdEncoding.DecodeString("HyqWP6q2XNu8SE32nf2pcQ==")
   if err != nil {
      t.Fatal(err)
   }
   checksum, err := base64.StdEncoding.DecodeString("KHc2PIih8ko=")
   if err != nil {
      t.Fatal(err)
   }
   payload, err := chain_data.LicenseRequestBytes(
      signingKey, kid, "ff-41f446bd-1474247",
      "http://license.9c9media.ca/playready", checksum,
   )
   if err != nil {
      t.Fatal(err)
   }
   data, err = json.Marshal(map[string]any{
      "payload": payload,
      "playbackContext": map[string]any{
         "contentId": 3300246,
         "contentpackageId": 8401705,
         "destinationId": 1880,
         "platformId": 1,
         "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2OTk2N2RhOWM5M2VlZjVkZjIwZjg3MTIiLCJzY29wZSI6ImFjY291bnQ6d3JpdGUgZGVmYXVsdCBtYXR1cml0eTphZHVsdCIsImlzcyI6Imh0dHBzOi8vYWNjb3VudC5iZWxsbWVkaWEuY2EiLCJjb250ZXh0Ijp7InByb2ZpbGVfaWQiOiI2OTk3MGVmYTczMTc2ZDJiMmU1M2E1YTMiLCJicmFuZF9pZHMiOlsiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTExIiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE0IiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE1Il19LCJleHAiOjE3NzUxNzcwNTEsImlhdCI6MTc3NTE2MjY1MSwidmVyc2lvbiI6IlYyIiwianRpIjoiMTRmYzI5OTktOGE5Yy00MGM3LWJhZmQtZjk0NTgwMTY4OGViIiwiYXV0aG9yaXRpZXMiOlsiUkVHVUxBUl9VU0VSIl0sImNsaWVudF9pZCI6ImNyYXZlLXdlYiJ9.mAsFKgZ0ez7LAYD30E0okAryrcVMtE0RvdjXS9i7j6wHY6B_w3snV-_kE5r-x0yvvQISaVBYmbUSkrSKzq_XEElZCWzJKyGzz28eyRkQJ-Jx2sigEmuA-vyLRaqcz3bK09fKbg4c1ekIv9uOTV2tJqnbP4cXMu7Cazp_thhQ3HtXyA9rzDm4vhoyhTkoo0mTKs--uhpxgO03UbuR7zPWbbAQsvy0yWCjgaEf61xKG6G9j6qp95g5cbt43UYv0OMzKZRAdu_61r8nGG3eTiqP_nyUu1fVDAm9Eb8AqHxdz7CnFcWyMEysMdAKD6NneukC9cLW2LtjBWYw0XaSLsBu9w",
      },
   })
   if err != nil {
      t.Fatal(err)
   }
   req, err := http.NewRequest(
      "POST", "https://license.9c9media.com/playready", bytes.NewReader(data),
   )
   if err != nil {
      t.Fatal(err)
   }
   t.Log(req.URL)
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   data, err = io.ReadAll(resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   if resp.StatusCode != http.StatusOK {
      t.Fatal(string(data))
   }
   licenseData, err := ParseLicense(data)
   if err != nil {
      t.Fatal(err)
   }
   key, err := licenseData.Decrypt(encryptKey)
   if err != nil {
      t.Fatal(err)
   }
   t.Logf("%x", key)
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
