package widevine

import (
   "bytes"
   "encoding/hex"
   "errors"
   "io"
   "net/http"
   "os"
   "testing"
)

var tests = []struct{
   content_id  string
   key_id      string
   license string
   web     string
}{
   {
      content_id:  "895914f0e55cccdd3952c6572979b582-mc-0-139-0-0",
      key_id:      "895914f0e55cccdd3952c6572979b582",
      license: "https://prod-kami.wuaki.tv/v1/licensing/wvm/8d9bb252-c21a-49b9-a925-735fd23f1aaf?uuid=8d9bb252-c21a-49b9-a925-735fd23f1aaf",
      web:     "https://rakuten.tv/pt/movies/bound",
   },
   {
      content_id:  "ff-ef3764fa-1352343",
      key_id:      "d55c7a4cc1c5208d6759098bbce00dba",
      license: "https://license.9c9media.ca/widevine",
      web:     "https://ctv.ca/movies/barbie",
   },
}

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
   private_key, err := ParsePrivateKey(pem_bytes)
   if err != nil {
      t.Fatal(err)
   }
   for _, test := range tests {
      t.Log(test.web)
      key_id, err := hex.DecodeString(test.key_id)
      if err != nil {
         t.Fatal(err)
      }
      // 1. Create the PsshData struct
      pssh := PsshData{
         ContentId: []byte(test.content_id),
         KeyIds: [][]byte{key_id},
      }
      // 2. Build the License Request directly from the pssh struct
      req_bytes, err := pssh.BuildLicenseRequest(client_id)
      if err != nil {
         t.Fatal(err)
      }
      // 3. Sign the request
      signed_bytes, err := BuildSignedMessage(req_bytes, private_key)
      if err != nil {
         t.Fatalf("Failed to create signed request: %v", err)
      }
      // 4. Send to License Server
      signed_bytes, err = post(test.license, signed_bytes)
      if err != nil {
         t.Fatal(err)
      }
      // 5. Parse Response
      keys, err := ParseLicenseResponse(signed_bytes, req_bytes, private_key)
      if err != nil {
         t.Fatal(err)
      }
      // 6. Verify Key
      found_key, err := GetKey(keys, key_id)
      if err != nil {
         t.Fatal(err)
      }
      t.Logf("%x", found_key)
   }
}

func post(link string, data []byte) ([]byte, error) {
   resp, err := http.Post(link, "", bytes.NewReader(data))
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      return nil, errors.New(resp.Status)
   }
   return io.ReadAll(resp.Body)
}
