package widevine

import (
   "fmt"

   "41.neocities.org/protobuf"
)

// License is the message containing the keys and policies.
type License struct {
   Id     *LicenseIdentification
   Policy *Policy
   Keys   []*KeyContainer
}

// KeyContainer represents a single key (e.g., a content key).
type KeyContainer struct {
   ID   []byte
   IV   []byte
   Key  []byte
   Type KeyType
}

// ParseLicense populates the License struct from a protobuf message.
func (l *License) ParseLicense(msg protobuf.Message) error {
   l.Keys = []*KeyContainer{} // Clear any existing keys

   for _, field := range msg {
      switch field.Tag.FieldNum {
      case 1: // id
         l.Id = &LicenseIdentification{}
         if err := l.Id.Parse(field.Message); err != nil {
            return fmt.Errorf("failed to parse license identification: %w", err)
         }
      case 2: // policy
         l.Policy = &Policy{}
         if err := l.Policy.ParsePolicy(field.Message); err != nil {
            return fmt.Errorf("failed to parse policy: %w", err)
         }
      case 3: // key (repeated)
         key := &KeyContainer{}
         if err := key.Parse(field.Message); err != nil {
            return fmt.Errorf("failed to parse license key container: %w", err)
         }
         l.Keys = append(l.Keys, key)
      }
   }
   return nil
}

// Parse populates the KeyContainer struct from a protobuf message.
func (kc *KeyContainer) Parse(msg protobuf.Message) error {
   for _, field := range msg {
      switch field.Tag.FieldNum {
      case 1:
         kc.ID = field.Bytes
      case 2:
         kc.IV = field.Bytes
      case 3:
         kc.Key = field.Bytes
      case 4:
         kc.Type = KeyType(field.Numeric)
      }
   }
   return nil
}
