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
   payload, err := chain_data.LicenseRequestBytes(
      signingKey, kid, "ff-41f446bd-1474247",
      "http://license.9c9media.ca/playready",
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
   "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2OTk2N2RhOWM5M2VlZjVkZjIwZjg3MTIiLCJzY29wZSI6ImFjY291bnQ6d3JpdGUgZGVmYXVsdCBtYXR1cml0eTphZHVsdCIsImlzcyI6Imh0dHBzOi8vYWNjb3VudC5iZWxsbWVkaWEuY2EiLCJjb250ZXh0Ijp7InByb2ZpbGVfaWQiOiI2OTk3MGVmYTczMTc2ZDJiMmU1M2E1YTMiLCJicmFuZF9pZHMiOlsiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTExIiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE0IiwiMWQ3MmQ5OTBjYjc2NWRlN2U0MjExMTE1Il19LCJleHAiOjE3NzUxMDk1NTEsImlhdCI6MTc3NTA5NTE1MSwidmVyc2lvbiI6IlYyIiwianRpIjoiYTdkY2RlZTItMWUxZS00ZTEyLWI2MzctNDNiOWVjMjNhMmU1IiwiYXV0aG9yaXRpZXMiOlsiUkVHVUxBUl9VU0VSIl0sImNsaWVudF9pZCI6ImNyYXZlLXdlYiJ9.J8pZFvnFyL_q_anJZfBWGhgGKKMMB_vTnK_N5ueK6PlWoQCQhVYkPU-GK6kVaViB3NnlFwRZjLpMjx4jqxvMGL4Pp1SlQmXtHQGNlAFCtYu-0TuVGSswuxhG2sT5kOkfnW9EexYntJ6OUFlg4pT_HUDC3P0QblHWFQBunVyNEZFm8OZnDcVn1zYovyIha8S7O7TkJWiUdSDGqDxp1CuEYc_67wrODgTq2REgGh83SjilLiR4ahHLIdBlrYSSOqqcMxPFPCf9n4ThduhhpQVIqE2wH8NTIggBk6cQ1klugsD2cuylT4EUuo_iFhpBU0e80Wbrn6iWRlDHnYcEnV5UPA",
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
