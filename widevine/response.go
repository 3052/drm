package widevine

import (
   "41.neocities.org/protobuf"
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "encoding/binary"
   "errors"
   "fmt"
   "github.com/emmansun/gmsm/cbcmac"
   "github.com/emmansun/gmsm/padding"
)

// GetKey searches for a key by its ID in a slice of KeyContainers.
// If the key is found, it returns the key and a nil error.
// If the key is not found, it returns nil and an error.
func GetKey(keys []*KeyContainer, id []byte) ([]byte, error) {
   for _, key := range keys {
      if bytes.Equal(key.Id, id) {
         return key.Key, nil
      }
   }
   return nil, errors.New("key not found")
}

const (
   kWrappingKeyLabel    = "ENCRYPTION"
   kWrappingKeySizeBits = 128
)

type KeyContainer struct {
   Id  []byte
   Iv  []byte
   Key []byte
}

func ParseLicenseResponse(responseData []byte, originalRequestBytes []byte, privateKey *rsa.PrivateKey) ([]*KeyContainer, error) {
   var topLevelMessage protobuf.Message
   if err := topLevelMessage.Parse(responseData); err != nil {
      return nil, fmt.Errorf("failed to parse SignedMessage: %w", err)
   }
   typeField, _ := topLevelMessage.Field(1)
   if typeField == nil {
      return nil, errors.New("missing message type")
   }

   msgField, found := topLevelMessage.Field(2)
   if !found || msgField.Message == nil {
      return nil, errors.New("missing message payload")
   }

   switch typeField.Numeric {
   case 2: // LICENSE
      sessionKeyField, _ := topLevelMessage.Field(4)
      if sessionKeyField == nil {
         return nil, errors.New("missing session_key")
      }
      decKey, err := rsa.DecryptOAEP(sha1.New(), nil, privateKey, sessionKeyField.Bytes, nil)
      if err != nil {
         return nil, err
      }
      return decodeLicenseFromMessage(msgField.Message, decKey, originalRequestBytes)
   case 3: // ERROR_RESPONSE
      return nil, decodeErrorFromMessage(msgField.Message)
   }
   return nil, fmt.Errorf("unsupported message type: %d", typeField.Numeric)
}

func decodeLicenseFromMessage(message protobuf.Message, sessionKey []byte, requestBytes []byte) ([]*KeyContainer, error) {
   cmacCipher, _ := aes.NewCipher(sessionKey)
   kdfInput := append([]byte{0x01}, []byte(kWrappingKeyLabel)...)
   kdfInput = append(kdfInput, 0x00)
   kdfInput = append(kdfInput, requestBytes...)
   sizeBytes := make([]byte, 4)
   binary.BigEndian.PutUint32(sizeBytes, kWrappingKeySizeBits)
   kdfInput = append(kdfInput, sizeBytes...)

   derivedKey := cbcmac.NewCMAC(cmacCipher, 16).MAC(kdfInput)
   ckCipher, _ := aes.NewCipher(derivedKey)

   var keys []*KeyContainer
   it := message.Iterator(3)
   for it.Next() {
      if it.Field().Message == nil {
         continue
      }
      kc := &KeyContainer{}
      m := it.Field().Message
      if f, ok := m.Field(1); ok {
         kc.Id = f.Bytes
      }
      if f, ok := m.Field(2); ok {
         kc.Iv = f.Bytes
      }
      if f, ok := m.Field(3); ok {
         dec := cipher.NewCBCDecrypter(ckCipher, kc.Iv)
         plain := make([]byte, len(f.Bytes))
         dec.CryptBlocks(plain, f.Bytes)
         unpadded, _ := padding.NewPKCS7Padding(aes.BlockSize).Unpad(plain)
         kc.Key = unpadded
      }
      keys = append(keys, kc)
   }
   return keys, nil
}
