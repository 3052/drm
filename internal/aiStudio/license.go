package widevine

import (
   "fmt"

   "41.neocities.org/protobuf"
)

// License is the message containing the keys and policies.
type License struct {
   Keys   []*License_Key
   Policy *Policy
   // ID is used as the session key for license renewals.
   ID []byte
   // Other fields like LicenseStartTime etc. can be added here if needed.
}

// License_Key represents a single key (e.g., a content key).
type License_Key struct {
   ID        []byte
   Type      KeyType
   Key       []byte
   Encrypted bool // Indicates if the Key field is encrypted
}

// ParseLicense populates the License struct from a protobuf message.
func (l *License) ParseLicense(msg protobuf.Message) error {
   l.Keys = []*License_Key{} // Clear any existing keys

   for _, field := range msg {
      switch field.Tag.FieldNum {
      case 1: // Repeated field for Keys
         key := &License_Key{}
         if err := key.ParseKey(field.Message); err != nil {
            return fmt.Errorf("failed to parse license key: %w", err)
         }
         l.Keys = append(l.Keys, key)
      case 2: // Policy message
         l.Policy = &Policy{}
         if err := l.Policy.ParsePolicy(field.Message); err != nil {
            return fmt.Errorf("failed to parse policy: %w", err)
         }
      case 3: // ID (Session Key)
         l.ID = field.Bytes
      }
   }
   return nil
}

// ParseKey populates the License_Key struct from a protobuf message.
func (lk *License_Key) ParseKey(msg protobuf.Message) error {
   for _, field := range msg {
      switch field.Tag.FieldNum {
      case 1:
         lk.ID = field.Bytes
      case 2:
         lk.Type = KeyType(field.Numeric)
      case 3:
         lk.Key = field.Bytes
      case 4:
         lk.Encrypted = field.Numeric == 1
      }
   }
   return nil
}
