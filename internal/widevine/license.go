package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/rsa"
)

// KeyContainer holds the parsed and decrypted content key from a license.
type KeyContainer struct {
   ID  []byte
   IV  []byte
   Key []byte // This holds the DECRYPTED key.
}

// License reflects the structure of the Widevine License protobuf.
type License struct {
   Policy *protobuf.Field
   Keys   []*KeyContainer
}

// decodeLicenseFromMessage constructs a License struct from a pre-parsed protobuf message
// and decrypts the content keys using the provided private key.
func decodeLicenseFromMessage(message protobuf.Message, privateKey *rsa.PrivateKey) (*License, error) {
   policy, _ := message.Field(2)

   var keys []*KeyContainer
   it := message.Iterator(3) // Iterator for field number 3 (key)
   for it.Next() {
      keyField := it.Field()
      if keyField.Message == nil {
         continue // Skip if it's not a valid message
      }

      kc := &KeyContainer{}
      embeddedKeyContainer := keyField.Message

      if idField, found := embeddedKeyContainer.Field(1); found {
         kc.ID = idField.Bytes
      }
      if ivField, found := embeddedKeyContainer.Field(2); found {
         kc.IV = ivField.Bytes
      }
      if keyDataField, found := embeddedKeyContainer.Field(3); found {
         decryptedKey, err := decryptKey(privateKey, keyDataField.Bytes)
         if err == nil {
            kc.Key = decryptedKey
         }
         // Silently fail on decryption error, key will be nil.
      }
      keys = append(keys, kc)
   }

   return &License{
      Policy: policy,
      Keys:   keys,
   }, nil
}
