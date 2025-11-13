package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/aes"
   "crypto/cipher"
   "encoding/binary"
   "errors"
   "fmt"

   "github.com/emmansun/gmsm/cbcmac"
   "github.com/emmansun/gmsm/padding"
)

// KeyContainer holds the parsed and decrypted content key from a license.
type KeyContainer struct {
   ID  []byte
   IV  []byte
   Key []byte // This now holds the fully DECRYPTED key.
}

// Constants used for the key derivation function (KDF).
const (
   kWrappingKeyLabel    = "ENCRYPTION"
   kWrappingKeySizeBits = 128
)

// decodeLicenseFromMessage constructs a slice of KeyContainers from a pre-parsed protobuf message
// and completes the full key decryption process.
func decodeLicenseFromMessage(message protobuf.Message, decryptedSessionKey []byte, originalRequestBytes []byte) ([]*KeyContainer, error) {
   // Step 1: Create an initial cipher from the decrypted session key.
   cmacCipher, err := aes.NewCipher(decryptedSessionKey)
   if err != nil {
      return nil, fmt.Errorf("failed to create AES cipher from session key: %w", err)
   }

   // Step 2: Build the KDF input.
   var kdfInput []byte
   kdfInput = append(kdfInput, 0x01)
   kdfInput = append(kdfInput, []byte(kWrappingKeyLabel)...)
   kdfInput = append(kdfInput, 0x00)
   kdfInput = append(kdfInput, originalRequestBytes...)
   sizeBytes := make([]byte, 4)
   binary.BigEndian.PutUint32(sizeBytes, kWrappingKeySizeBits)
   kdfInput = append(kdfInput, sizeBytes...)

   // Step 3: Use CMAC to derive the final content key encryption key.
   cmac := cbcmac.NewCMAC(cmacCipher, 16)
   derivedKey := cmac.MAC(kdfInput)

   // Step 4: Create the final AES cipher from the derived key.
   contentKeyCipher, err := aes.NewCipher(derivedKey)
   if err != nil {
      return nil, fmt.Errorf("failed to create AES cipher from derived key: %w", err)
   }

   var keys []*KeyContainer
   it := message.Iterator(3) // Iterator for field number 3 (key container)
   for it.Next() {
      keyField := it.Field()
      if keyField.Message == nil {
         continue
      }

      kc := &KeyContainer{}
      embeddedKeyContainer := keyField.Message

      if idField, found := embeddedKeyContainer.Field(1); found {
         kc.ID = idField.Bytes
      }
      if ivField, found := embeddedKeyContainer.Field(2); found {
         kc.IV = ivField.Bytes
      }

      // Step 5: Decrypt the actual content key.
      if keyDataField, found := embeddedKeyContainer.Field(3); found {
         encryptedKey := keyDataField.Bytes
         if len(encryptedKey)%aes.BlockSize != 0 {
            return nil, errors.New("encrypted key is not a multiple of the block size")
         }
         if kc.IV == nil {
            return nil, errors.New("key container is missing IV, cannot decrypt")
         }

         // Use AES-CBC to decrypt.
         decrypter := cipher.NewCBCDecrypter(contentKeyCipher, kc.IV)
         decryptedPaddedKey := make([]byte, len(encryptedKey))
         decrypter.CryptBlocks(decryptedPaddedKey, encryptedKey)

         // Remove PKCS#7 padding using the provided library.
         pkcs7 := padding.NewPKCS7Padding(aes.BlockSize)
         unpaddedKey, err := pkcs7.Unpad(decryptedPaddedKey)
         if err != nil {
            return nil, fmt.Errorf("failed to unpad decrypted key: %w", err)
         }
         kc.Key = unpaddedKey
      }
      keys = append(keys, kc)
   }

   return keys, nil
}
