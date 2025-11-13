package widevine

import (
   "41.neocities.org/protobuf"
   "bytes"
   "crypto/rand"
   "crypto/rsa"
   "crypto/sha1"
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
   Keys  []*KeyContainer
   Error *LicenseError
}

// GetKey searches for a key by its ID in the license response.
// It returns the key and true if found, otherwise it returns nil and false.
func (pr *ParsedResponse) GetKey(id []byte) ([]byte, bool) {
   if pr.Keys == nil {
      return nil, false
   }
   for _, keyContainer := range pr.Keys {
      if bytes.Equal(keyContainer.ID, id) {
         return keyContainer.Key, true
      }
   }
   return nil, false
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
// It now returns a slice of KeyContainers directly in the ParsedResponse.
func ParseLicenseResponse(responseData []byte, originalRequestBytes []byte, privateKey *rsa.PrivateKey) (*ParsedResponse, error) {
   var topLevelMessage protobuf.Message
   if err := topLevelMessage.Parse(responseData); err != nil {
      return nil, fmt.Errorf("failed to parse top-level SignedMessage: %w", err)
   }

   typeField, _ := topLevelMessage.Field(1)
   if typeField == nil {
      return nil, fmt.Errorf("response is missing message type identifier")
   }
   msgType := typeField.Numeric

   switch msgType {
   case 2: // MessageType LICENSE = 2
      msgField, found := topLevelMessage.Field(2)
      if !found || msgField.Message == nil {
         return nil, fmt.Errorf("license response is missing the main message payload")
      }
      embeddedMessage := msgField.Message

      sessionKeyField, found := topLevelMessage.Field(4)
      if !found {
         return nil, fmt.Errorf("license response is missing the session_key")
      }
      decryptedSessionKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, sessionKeyField.Bytes, nil)
      if err != nil {
         return nil, fmt.Errorf("failed to decrypt response session key: %w", err)
      }

      keys, err := decodeLicenseFromMessage(embeddedMessage, decryptedSessionKey, originalRequestBytes)
      if err != nil {
         return nil, fmt.Errorf("failed to decode license message: %w", err)
      }
      return &ParsedResponse{Keys: keys}, nil

   case 3: // MessageType ERROR_RESPONSE = 3
      msgField, found := topLevelMessage.Field(2)
      if !found || msgField.Message == nil {
         return nil, fmt.Errorf("error response is missing the main message payload")
      }
      licenseError, err := decodeErrorFromMessage(msgField.Message)
      if err != nil {
         return nil, fmt.Errorf("failed to decode error message: %w", err)
      }
      return &ParsedResponse{Error: licenseError}, nil
   }

   return nil, fmt.Errorf("unsupported message type in response: %d", msgType)
}
