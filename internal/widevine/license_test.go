package widevine

import (
   "bytes"
   "encoding/base64"
   "fmt"
   "io"
   "net/http"
   "os"
   "testing"
)

func TestLicense(t *testing.T) {
   keyPath := `C:\Users\Steven\AppData\Local\L3\private_key.pem`
   pemBytes, err := os.ReadFile(keyPath)
   if err != nil {
      if os.IsNotExist(err) {
         t.Fatalf("skipping test: test key file not found at %s", keyPath)
      }
      t.Fatalf("Failed to read private key file: %v", err)
   }
   privateKey, err := ParsePrivateKey(pemBytes)
   if err != nil {
      t.Fatalf("Failed to parse private key from %s: %v", keyPath, err)
   }
   client_id, err := os.ReadFile(
      `C:\Users\Steven\AppData\Local\L3\client_id.bin`,
   )
   if err != nil {
      t.Fatal(err)
   }
   content_id, err := base64.StdEncoding.DecodeString(ctv.content_id)
   if err != nil {
      t.Fatal(err)
   }
   key_id, err := base64.StdEncoding.DecodeString(ctv.key_id)
   if err != nil {
      t.Fatal(err)
   }
   pssh := WidevinePsshData{
      ContentID: content_id,
      KeyIDs:    [][]byte{key_id},
   }
   psshBytes, err := pssh.Encode()
   if err != nil {
      t.Fatal(err)
   }
   req := NewLicenseRequest(client_id, psshBytes, 1)
   reqBytes, err := req.Encode()
   if err != nil {
      t.Fatalf("Failed to encode request: %v", err)
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
   for _, key := range parsed.License.Keys {
      fmt.Printf("%+v\n", key)
   }
}

var ctv = struct {
   content_id  string
   key_id      string
   url_ctv     string
   url_license string
}{
   content_id:  "ZmYtOGYyNjEzYWUtNTIxNTAx",
   key_id:      "A98dtspZsb9/z++3IHp0Dw==",
   url_ctv:     "ctv.ca/movies/fools-rush-in-57470",
   url_license: "https://license.9c9media.ca/widevine",
}
