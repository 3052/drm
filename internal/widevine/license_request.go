package widevine

import (
   "41.neocities.org/protobuf"
)

// LicenseRequest is the core message for requesting a license.
type LicenseRequest struct {
   // Pre-encoded ClientIdentification message.
   ClientID []byte
   // Information about the content.
   ContentID *ContentIdentification
   // The type of the request (e.g., new or renewal).
   Type RequestType
   // A key control nonce.
   KeyControlNonce uint32
}

// ToProto creates a protobuf.Message from the LicenseRequest struct.
func (lr *LicenseRequest) ToProto() protobuf.Message {
   msg := protobuf.Message{}
   if lr.ClientID != nil {
      msg = append(msg, protobuf.NewBytes(1, lr.ClientID))
   }
   if lr.ContentID != nil {
      msg = append(msg, protobuf.NewMessage(2, lr.ContentID.ToProto()...))
   }
   // The Type field is an enum, which is encoded as a Varint.
   msg = append(msg, protobuf.NewVarint(3, uint64(lr.Type)))
   if lr.KeyControlNonce != 0 {
      msg = append(msg, protobuf.NewFixed32(7, lr.KeyControlNonce))
   }
   return msg
}
