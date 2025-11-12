package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/rsa"
)

// KeyContainer holds the parsed and decrypted content key from a license.
type KeyContainer struct {
   ID  []byte
   IV  []byte
   Key []byte // This will hold the DECRYPTED key.
}

// License reflects the structure of the Widevine License protobuf.
type License struct {
   Policy *protobuf.Field
   Keys   []*KeyContainer
}

// ParseLicense deserializes a License from the protobuf wire format and decrypts
// the content keys using the provided private key.
func ParseLicense(data []byte, privateKey *rsa.PrivateKey) (*License, error) {
   var message protobuf.Message
   if err := message.Parse(data); err != nil {
      return nil, err
   }

   policy, _ := message.Field(2)

   var keys []*KeyContainer
   it := message.Iterator(3) // Iterator for field number 3 (key)
   for it.Next() {
      keyField := it.Field()
      if keyField.Message == nil {
         continue // Skip if it's not a valid message
      }

      kc := &KeyContainer{}

      // Field 1: id
      if idField, found := keyField.Message.Field(1); found {
         kc.ID = idField.Bytes
      }

      // Field 2: iv
      if ivField, found := keyField.Message.Field(2); found {
         kc.IV = ivField.Bytes
      }

      // Field 3: key (This is the encrypted content key)
      if keyDataField, found := keyField.Message.Field(3); found {
         decryptedKey, err := decryptKey(privateKey, keyDataField.Bytes)
         if err == nil {
            kc.Key = decryptedKey
         }
         // If decryption fails, kc.Key will remain nil.
         // You could add more robust error handling here if needed.
      }

      keys = append(keys, kc)
   }

   return &License{
      Policy: policy,
      Keys:   keys,
   }, nil
}
