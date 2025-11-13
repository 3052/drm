package widevine

import (
   "bytes"
   "encoding/hex"
   "io"
   "net/http"
   "os"
   "testing"
)

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

func TestCtv(t *testing.T) {
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
   var psshValue Pssh
   psshValue.ContentId = []byte(ctv.content_id)
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
   resp, err := http.Post(ctv.url_license, "", bytes.NewReader(data))
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
   key_id, err := hex.DecodeString(ctv.key_id)
   if err != nil {
      t.Fatal(err)
   }
   key, err := hex.DecodeString(ctv.key)
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
