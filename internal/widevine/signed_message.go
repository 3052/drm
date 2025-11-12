package widevine

import (
   "41.neocities.org/protobuf"
)

// SignedMessage reflects the structure of the Widevine SignedMessage protobuf.
type SignedMessage struct {
   Type      *protobuf.Field
   Msg       *protobuf.Field
   Signature *protobuf.Field
}

// NewSignedMessage creates and initializes a new SignedMessage.
func NewSignedMessage(messageType int, msg []byte, signature []byte) *SignedMessage {
   return &SignedMessage{
      Type:      protobuf.NewVarint(1, uint64(messageType)),
      Msg:       protobuf.NewBytes(2, msg),
      Signature: protobuf.NewBytes(3, signature),
   }
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
