package widevine

import (
   "bytes"
   "encoding/hex"
   "io"
   "net/http"
   "os"
   "testing"
)

func TestLicense(t *testing.T) {
   client_id, err := os.ReadFile(
      `C:\Users\Steven\AppData\Local\L3\client_id.bin`,
   )
   if err != nil {
      t.Fatal(err)
   }
   var pssh WidevinePsshData
   pssh.ContentID = []byte(ctv.content_id)
   psshBytes, err := pssh.Encode()
   if err != nil {
      t.Fatal(err)
   }
   req := NewLicenseRequest(client_id, psshBytes, 1)
   reqBytes, err := req.Encode()
   if err != nil {
      t.Fatal(err)
   }
   pemBytes, err := os.ReadFile(
      `C:\Users\Steven\AppData\Local\L3\private_key.pem`,
   )
   if err != nil {
      t.Fatal(err)
   }
   privateKey, err := ParsePrivateKey(pemBytes)
   if err != nil {
      t.Fatal(err)
   }
   signedMsg, err := NewSignedRequest(privateKey, reqBytes)
   if err != nil {
      t.Fatalf("Failed to create signed request: %v", err)
   }
   if signedMsg.SessionKey == nil || len(signedMsg.SessionKey.Bytes) == 0 {
      t.Fatal("SessionKey was not automatically generated in the signed request")
   }
   verifySignature(t, &privateKey.PublicKey, signedMsg.Msg.Bytes, signedMsg.Signature.Bytes)
   signedBytes, err := signedMsg.Encode()
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(ctv.url_license, "", bytes.NewReader(signedBytes))
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   signedBytes, err = io.ReadAll(resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   parsed, err := ParseLicenseResponse(signedBytes, reqBytes, privateKey)
   if err != nil {
      t.Fatal(err)
   }
   key_id, err := hex.DecodeString(ctv.key_id)
   if err != nil {
      t.Fatal(err)
   }
   key, err := hex.DecodeString(ctv.key)
   if err != nil {
      t.Fatal(err)
   }
   key1, ok := parsed.GetKey(key_id)
   if !ok {
      t.Fatal("GetKey")
   }
   if !bytes.Equal(key1, key) {
      t.Fatal("!bytes.Equal")
   }
}

var ctv = struct {
   content_id  string
   key         string
   key_id      string
   url_ctv     string
   url_license string
}{
   content_id:  "ff-e58adb7f-1383420",
   key:         "7a480828e337e2f7b046fddce0fd5d17",
   key_id:      "e9f3053c404e531a4794dc41ca305457",
   url_ctv:     "https://ctv.ca/movies/the-hurt-locker",
   url_license: "https://license.9c9media.ca/widevine",
}
