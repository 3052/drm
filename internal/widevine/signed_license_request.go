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
   // The session key used for signing.
   SessionKey []byte
   // The signature algorithm used.
   SignatureAlgorithm SignatureAlgorithm
}

// ToProto creates a protobuf.Message from the SignedLicenseRequest struct.
func (slr *SignedLicenseRequest) ToProto() protobuf.Message {
   msg := protobuf.Message{}
   // The Type field is an enum, which is encoded as a Varint.
   msg = append(msg, protobuf.NewVarint(1, uint64(slr.Type)))
   if slr.Msg != nil {
      msg = append(msg, protobuf.NewBytes(2, slr.Msg))
   }
   if slr.Signature != nil {
      msg = append(msg, protobuf.NewBytes(3, slr.Signature))
   }
   if slr.SessionKey != nil {
      msg = append(msg, protobuf.NewBytes(5, slr.SessionKey))
   }
   msg = append(msg, protobuf.NewVarint(4, uint64(slr.SignatureAlgorithm)))
   return msg
}
