package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/rsa"
)

// SignedMessage reflects the structure of the Widevine SignedMessage protobuf.
type SignedMessage struct {
   Type      *protobuf.Field
   Msg       *protobuf.Field
   Signature *protobuf.Field
}

// NewSignedRequest creates a new SignedMessage for a license request.
// It takes the license request bytes and signs them with the provided private key.
func NewSignedRequest(privateKey *rsa.PrivateKey, msg []byte) (*SignedMessage, error) {
   signature, err := signMessage(privateKey, msg)
   if err != nil {
      return nil, err
   }

   return &SignedMessage{
      Type:      protobuf.NewVarint(1, 1), // MessageType LICENSE_REQUEST = 1
      Msg:       protobuf.NewBytes(2, msg),
      Signature: protobuf.NewBytes(3, signature),
   }, nil
}

// Encode serializes the SignedMessage into the protobuf wire format.
func (sm *SignedMessage) Encode() ([]byte, error) {
   message := protobuf.Message{sm.Type, sm.Msg, sm.Signature}
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

   return &SignedMessage{
      Type:      msgType,
      Msg:       msg,
      Signature: sig,
   }, nil
}
