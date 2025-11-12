package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/rsa"
)

// SignedMessage reflects the structure of the Widevine SignedMessage protobuf.
type SignedMessage struct {
   Type       *protobuf.Field
   Msg        *protobuf.Field
   Signature  *protobuf.Field
   SessionKey *protobuf.Field
}

// NewSignedRequest creates a new SignedMessage for a license request.
// It takes the license request bytes and signs them with the provided private key.
// The sessionKey is optional and can be nil.
func NewSignedRequest(privateKey *rsa.PrivateKey, msg, sessionKey []byte) (*SignedMessage, error) {
   signature, err := signMessage(privateKey, msg)
   if err != nil {
      return nil, err
   }

   sm := &SignedMessage{
      Type:      protobuf.NewVarint(1, 1), // MessageType LICENSE_REQUEST = 1
      Msg:       protobuf.NewBytes(2, msg),
      Signature: protobuf.NewBytes(3, signature),
   }

   if sessionKey != nil {
      sm.SessionKey = protobuf.NewBytes(4, sessionKey)
   }

   return sm, nil
}

// Encode serializes the SignedMessage into the protobuf wire format.
func (sm *SignedMessage) Encode() ([]byte, error) {
   message := protobuf.Message{sm.Type, sm.Msg, sm.Signature}
   if sm.SessionKey != nil {
      message = append(message, sm.SessionKey)
   }
   return message.Encode()
}

// ParseSignedMessage deserializes a SignedMessage from the protobuf wire format.
func ParseSignedMessage(data []byte) (*SignedMessage, error) {
   var message protobuf.Message
   if err := message.Parse(data); err != nil {
      return nil, err
   }

   msgType, _ := message.Field(1)
   msg, _ := message.Field(2)
   sig, _ := message.Field(3)
   sessionKey, _ := message.Field(4)

   return &SignedMessage{
      Type:       msgType,
      Msg:        msg,
      Signature:  sig,
      SessionKey: sessionKey,
   }, nil
}
