package widevine

import "41.neocities.org/protobuf"

// LicenseIdentification corresponds to the message of the same name.
type LicenseIdentification struct {
   RequestID            []byte
   SessionID            []byte
   PurchaseID           []byte
   Type                 LicenseType
   Version              int32
   ProviderSessionToken []byte
}

// Parse populates the struct from a protobuf message.
func (li *LicenseIdentification) Parse(msg protobuf.Message) error {
   for _, field := range msg {
      switch field.Tag.FieldNum {
      case 1:
         li.RequestID = field.Bytes
      case 2:
         li.SessionID = field.Bytes
      case 3:
         li.PurchaseID = field.Bytes
      case 4:
         li.Type = LicenseType(field.Numeric)
      case 5:
         li.Version = int32(field.Numeric)
      case 6:
         li.ProviderSessionToken = field.Bytes
      }
   }
   return nil
}
