package widevine

import (
   "41.neocities.org/protobuf"
)

// ContentIdentification identifies the content for which the license is being requested.
type ContentIdentification struct {
   // The 'widevine_pssh_data' field.
   WidevinePsshData *WidevinePsshData
   // The license type (e.g., streaming, offline).
   LicenseType LicenseType
   // The unique identifier for the request.
   RequestID []byte
}

// ToProto creates a protobuf.Message from the ContentIdentification struct.
func (ci *ContentIdentification) ToProto() protobuf.Message {
   msg := protobuf.Message{}
   if ci.WidevinePsshData != nil {
      // Field 1: The embedded WidevinePsshData message.
      msg = append(msg, protobuf.NewMessage(1, ci.WidevinePsshData.ToProto()...))
   }
   // Field 2: The license type.
   msg = append(msg, protobuf.NewVarint(2, uint64(ci.LicenseType)))
   if ci.RequestID != nil {
      // Field 5: The request ID.
      msg = append(msg, protobuf.NewBytes(5, ci.RequestID))
   }
   return msg
}
