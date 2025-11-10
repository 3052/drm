package widevine

import (
   "41.neocities.org/protobuf"
)

// ContentIdentification identifies the content for which the license is being requested.
type ContentIdentification struct {
   // The PSSH data for the content.
   PSSH []byte
   // The license type (e.g., streaming, offline).
   LicenseType LicenseType
   // The unique identifier for the request.
   RequestID []byte
}

// ToProto creates a protobuf.Message from the ContentIdentification struct.
func (ci *ContentIdentification) ToProto() protobuf.Message {
   msg := protobuf.Message{}
   if ci.PSSH != nil {
      msg = append(msg, protobuf.NewBytes(1, ci.PSSH))
   }
   msg = append(msg, protobuf.NewVarint(2, uint64(ci.LicenseType)))
   if ci.RequestID != nil {
      msg = append(msg, protobuf.NewBytes(5, ci.RequestID))
   }
   return msg
}
