package widevine

import (
   "fmt"
   "os"
   "testing"
)

const keyboxFilePath = "internal/2025/9/27/HRE_6683_HAIERATV_dev_0000271571 [13764].bin"

func TestKeybox(t *testing.T) {
   data, err := os.ReadFile(keyboxFilePath)
   if err != nil {
      t.Fatal(err)
   }
   var kbox keybox
   err = kbox.unmarshal(data)
   if err != nil {
      t.Fatal(err)
   }
   fmt.Println(&kbox)
}
