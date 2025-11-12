package widevine

import (
   "bytes"
   "encoding/base64"
   "io"
   "net/http"
   "os"
   "testing"
)

var ctv_ca = struct {
   content_id  string
   key         string
   key_id      string
   url_ctv     string
   url_license string
}{
   content_id:  "ZmYtOGYyNjEzYWUtNTIxNTAx",
   key:         "xQ87t+z5cLOVgxDdSgHyoA==",
   key_id:      "A98dtspZsb9/z++3IHp0Dw==",
   url_ctv:     "ctv.ca/movies/fools-rush-in-57470",
   url_license: "https://license.9c9media.ca/widevine",
}

func TestCtv(t *testing.T) {
   key, err := base64.StdEncoding.DecodeString(ctv_ca.key)
   if err != nil {
      t.Fatal(err)
   }
   cache, err := os.UserCacheDir()
   if err != nil {
      t.Fatal(err)
   }
   private_key, err := os.ReadFile(cache + "/L3/private_key.pem")
   if err != nil {
      t.Fatal(err)
   }
   client_id, err := os.ReadFile(cache + "/L3/client_id.bin")
   if err != nil {
      t.Fatal(err)
   }
   key_id, err := base64.StdEncoding.DecodeString(ctv_ca.key_id)
   if err != nil {
      t.Fatal(err)
   }
   var psshValue Pssh
   psshValue.KeyIds = [][]byte{key_id}
   psshValue.ContentId, err = base64.StdEncoding.DecodeString(ctv_ca.content_id)
   if err != nil {
      t.Fatal(err)
   }
   psshData, err := psshValue.Encode()
   if err != nil {
      t.Fatal(err)
   }
   var module Cdm
   err = module.New(private_key, client_id, psshData)
   if err != nil {
      t.Fatal(err)
   }
   data, err := module.RequestBody()
   if err != nil {
      t.Fatal(err)
   }
   resp, err := http.Post(ctv_ca.url_license, "", bytes.NewReader(data))
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()
   data, err = io.ReadAll(resp.Body)
   if err != nil {
      t.Fatal(err)
   }
   if resp.StatusCode != http.StatusOK {
      t.Fatal(resp.Status)
   }
   var body ResponseBody
   err = body.Unmarshal(data)
   if err != nil {
      t.Fatal(err)
   }
   block, err := module.Block(body)
   if err != nil {
      t.Fatal(err)
   }
   for container := range body.Container() {
      if bytes.Equal(container.Id(), key_id) {
         key1, err := container.Key(block)
         if err != nil {
            t.Fatal(err)
         }
         if bytes.Equal(key1, key) {
            return
         }
      }
   }
   t.Fatal("key not found")
}
