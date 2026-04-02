package playReady

import (
   "bytes"
   "encoding/base64"
   "encoding/json"
   "fmt"
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
   fmt.Println(string(payload))
   data, err = json.Marshal(map[string]any{
      "payload": payload,
      "playbackContext": map[string]any{
         "contentId": 3300246,
         "contentpackageId": 8401705,
         "destinationId": 1880,
         "platformId": 1,
  "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2OTk2N2RhOWM5M2VlZjVkZjIwZjg3MTIiLCJzY29wZSI6ImFjY291bnQ6d3JpdGUgZGVmYXVsdCBtYXR1cml0eTphZHVsdCIsImlzcyI6Imh0dHBzOi8vYWNjb3VudC5iZWxsbWVkaWEuY2EiLCJjb250ZXh0Ijp7InByb2ZpbGVfaWQiOiI2OTk3MGVmYTczMTc2ZDJiMmU1M2E1YTMiLCJicmFuZF9pZHMiOlsiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTExIiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE0IiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE1Il19LCJleHAiOjE3NzUxMTg4NzksImlhdCI6MTc3NTEwNDQ3OSwidmVyc2lvbiI6IlYyIiwianRpIjoiODgyZDBlMjEtY2NkMS00YzM3LWEyODItZjNiOTljOWI0ZjNhIiwiYXV0aG9yaXRpZXMiOlsiUkVHVUxBUl9VU0VSIl0sImNsaWVudF9pZCI6ImNyYXZlLXdlYiJ9.V-o3nqFcJQVo55gVUM2NTPA2d-xVZfCZ4r3XTUuZMDNgntNGECwpMfEBP6GiiXaj3lLq1tw8sXdzAnzx513z-Vy14uDm0lkSO8c-dHU96mpsArwCBT4agu8CG7AkPzA33WBInC4pzH4oZBCOr2TqOiM92o3TUqeSuPgTzK9N234wYC7WBWmLqzckAUtxYo5zacbdLbk8JVtWcU3TgEvBiYwP-67oddHi2nWA0bTvmqV3oW98ljjG46eYZgn8ArV83jkkT9sH7gzHUh6RzazW_ietTi6k1yzogeaxBYrpcHmMv0S1z8QgFIotqFlii7r0Jr_i-mDknBCS_bzb-zAvhA",
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
