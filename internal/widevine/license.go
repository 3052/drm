package widevine

import (
   "41.neocities.org/protobuf"
)

// License reflects the structure of the Widevine License protobuf.
type License struct {
   Policy *protobuf.Field
   Key    []*protobuf.Field // Repeated field
}

// ParseLicense deserializes a License from the protobuf wire format.
func ParseLicense(data []byte) (*License, error) {
   var message protobuf.Message
   if err := message.Parse(data); err != nil {
      return nil, err
   }

   policy, _ := message.Field(2)

   var keys []*protobuf.Field
   it := message.Iterator(3)
   for it.Next() {
      keys = append(keys, it.Field())
   }

   return &License{
      Policy: policy,
      Key:    keys,
   }, nil
}
