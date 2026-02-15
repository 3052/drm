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
   cache, err := os.UserCacheDir()
   if err != nil {
      t.Fatal(err)
   }
   client_id, err := os.ReadFile(cache + "/L3/client_id.bin")
   if err != nil {
      t.Fatal(err)
   }
   pem_bytes, err := os.ReadFile(cache + "/L3/private_key.pem")
   if err != nil {
      t.Fatal(err)
   }
   // 1. Create the PsshData struct
   pssh := &PsshData{
      ContentId: []byte(ctv.content_id),
   }
   // 2. Build the License Request directly from the pssh struct
   req_bytes, err := pssh.BuildLicenseRequest(client_id)
   if err != nil {
      t.Fatal(err)
   }
   private_key, err := ParsePrivateKey(pem_bytes)
   if err != nil {
      t.Fatal(err)
   }
   // 3. Sign the request
   signed_bytes, err := BuildSignedMessage(req_bytes, private_key)
   if err != nil {
      t.Fatalf("Failed to create signed request: %v", err)
   }
   // 4. Send to License Server
   resp, err := http.Post(ctv.url_license, "", bytes.NewReader(signed_bytes))
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   signed_bytes, err = io.ReadAll(resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   // 5. Parse Response
   keys, err := ParseLicenseResponse(signed_bytes, req_bytes, private_key)
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
   // 6. Verify Key
   found_key, err := GetKey(keys, key_id)
   if err != nil {
      t.Fatal(err)
   }
   if !bytes.Equal(found_key, key) {
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
