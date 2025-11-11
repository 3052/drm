package widevine

import (
   "41.neocities.org/protobuf"
)

// SignedLicenseRequest is the message sent to the Widevine license server.
type SignedLicenseRequest struct {
   // The type of the message (e.g., license request).
   Type MessageType
   // The serialized LicenseRequest message.
   Msg []byte
   // The signature of the Msg field.
   Signature []byte
   // A session key for the current session.
   SessionKey []byte
}

// ToProto creates a protobuf.Message from the SignedLicenseRequest struct.
func (slr *SignedLicenseRequest) ToProto() protobuf.Message {
   msg := protobuf.Message{}
   msg = append(msg, protobuf.NewVarint(1, uint64(slr.Type)))
   if slr.Msg != nil {
      msg = append(msg, protobuf.NewBytes(2, slr.Msg))
   }
   if slr.Signature != nil {
      msg = append(msg, protobuf.NewBytes(3, slr.Signature))
   }
   if slr.SessionKey != nil {
      // Corrected field number to 4.
      msg = append(msg, protobuf.NewBytes(4, slr.SessionKey))
   }
   return msg
}
