package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/rsa"
   "crypto/sha1"
   "fmt"
)

// BuildSignedMessage creates and serializes a SignedMessage protobuf for a license request.
func BuildSignedMessage(msg []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
   signature, err := signMessage(privateKey, msg)
   if err != nil {
      return nil, err
   }

   // Build the message with its fields.
   message := protobuf.Message{
      protobuf.Varint(1, 1), // MessageType LICENSE_REQUEST = 1
      protobuf.Bytes(2, msg),
      protobuf.Bytes(3, signature),
   }

   return message.Encode()
}

// ParseLicenseResponse parses a response from the license server.
// It returns a slice of key containers on success.
// If the server responded with an error message, it returns a *LicenseError.
// For any other failures, it returns a standard Go error.
func ParseLicenseResponse(responseData []byte, originalRequestBytes []byte, privateKey *rsa.PrivateKey) ([]*KeyContainer, error) {
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

      // Decrypt the session key, passing nil for the random reader.
      decryptedSessionKey, err := rsa.DecryptOAEP(sha1.New(), nil, privateKey, sessionKeyField.Bytes, nil)
      if err != nil {
         return nil, fmt.Errorf("failed to decrypt response session key: %w", err)
      }

      return decodeLicenseFromMessage(embeddedMessage, decryptedSessionKey, originalRequestBytes)

   case 3: // MessageType ERROR_RESPONSE = 3
      msgField, found := topLevelMessage.Field(2)
      if !found || msgField.Message == nil {
         return nil, fmt.Errorf("error response is missing the main message payload")
      }

      // The server responded with a known error type.
      // Return nil for the keys and the LicenseError as the error.
      return nil, decodeErrorFromMessage(msgField.Message)
   }

   return nil, fmt.Errorf("unsupported message type in response: %d", msgType)
}
