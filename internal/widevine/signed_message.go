package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/rsa"
   "crypto/x509"
   "fmt"
)

// SignedMessage reflects the top-level structure of the Widevine SignedMessage protobuf.
// This is used internally by the parsing logic.
type SignedMessage struct {
   Type       *protobuf.Field
   Msg        *protobuf.Field
   Signature  *protobuf.Field
   SessionKey *protobuf.Field
}

// ParsedResponse is a user-friendly struct that contains the decoded content
// of a license server's response. Exactly one of the fields will be non-nil.
type ParsedResponse struct {
   License *License
   Error   *LicenseError
}

// NewSignedRequest creates a new SignedMessage for a license request.
// It signs the request message and automatically generates the session_key.
func NewSignedRequest(privateKey *rsa.PrivateKey, msg []byte) (*SignedMessage, error) {
   signature, err := signMessage(privateKey, msg)
   if err != nil {
      return nil, err
   }
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

// ParseLicenseResponse is the single function needed to parse a response from the license server.
// It parses the message once and returns a struct containing either the deciphered License
// or a LicenseError, avoiding wasteful re-parsing.
func ParseLicenseResponse(data []byte, privateKey *rsa.PrivateKey) (*ParsedResponse, error) {
   var topLevelMessage protobuf.Message
   if err := topLevelMessage.Parse(data); err != nil {
      return nil, fmt.Errorf("failed to parse top-level SignedMessage: %w", err)
   }

   msgField, found := topLevelMessage.Field(2)
   if !found || msgField.Message == nil {
      return nil, fmt.Errorf("response is missing the main message payload")
   }

   typeField, _ := topLevelMessage.Field(1)
   if typeField == nil {
      return nil, fmt.Errorf("response is missing message type identifier")
   }

   msgType := typeField.Numeric
   embeddedMessage := msgField.Message

   switch msgType {
   case 2: // MessageType LICENSE = 2
      license, err := decodeLicenseFromMessage(embeddedMessage, privateKey)
      if err != nil {
         return nil, fmt.Errorf("failed to decode license message: %w", err)
      }
      return &ParsedResponse{License: license}, nil

   case 3: // MessageType ERROR_RESPONSE = 3
      licenseError, err := decodeErrorFromMessage(embeddedMessage)
      if err != nil {
         return nil, fmt.Errorf("failed to decode error message: %w", err)
      }
      return &ParsedResponse{Error: licenseError}, nil
   }

   return nil, fmt.Errorf("unsupported message type in response: %d", msgType)
}
