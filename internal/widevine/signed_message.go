package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/rsa"
   "crypto/x509"
   "fmt"
)

// SignedMessage reflects the structure of the Widevine SignedMessage protobuf.
type SignedMessage struct {
   Type       *protobuf.Field
   Msg        *protobuf.Field
   Signature  *protobuf.Field
   SessionKey *protobuf.Field
}

// NewSignedRequest creates a new SignedMessage for a license request.
// It signs the request message and automatically generates the session_key
// (the public key) from the provided private key.
func NewSignedRequest(privateKey *rsa.PrivateKey, msg []byte) (*SignedMessage, error) {
   // Sign the core request message.
   signature, err := signMessage(privateKey, msg)
   if err != nil {
      return nil, err
   }

   // The session_key for the request is the client's public key,
   // serialized in the PKIX/SPKI format.
   publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
   if err != nil {
      return nil, fmt.Errorf("failed to marshal public key for session key: %w", err)
   }

   sm := &SignedMessage{
      Type:       protobuf.NewVarint(1, 1), // MessageType LICENSE_REQUEST = 1
      Msg:        protobuf.NewBytes(2, msg),
      Signature:  protobuf.NewBytes(3, signature),
      SessionKey: protobuf.NewBytes(4, publicKeyBytes),
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
