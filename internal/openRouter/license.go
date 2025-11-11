package widevine

import (
   "41.neocities.org/protobuf"
   "fmt"
)

// License holds data parsed from a license response.
type License struct {
   Keys []Key
}

// Key represents a single decryption key.
type Key struct {
   ID    []byte
   Value []byte
   Type  string
}

// keyTypeToString maps the key type enum to a human-readable string.
func keyTypeToString(keyType uint64) string {
   switch keyType {
   case 1:
      return "OPERATOR_SESSION"
   case 2:
      return "ENCRYPTION"
   case 3:
      return "SIGNING"
   case 4:
      return "CONTENT"
   default:
      return "UNKNOWN"
   }
}

// ParseLicenseResponse parses the raw license response from the Widevine server.
func ParseLicenseResponse(responseBytes []byte) (*License, error) {
   var signedMsg protobuf.Message
   if err := signedMsg.Parse(responseBytes); err != nil {
      return nil, fmt.Errorf("failed to parse SignedMessage: %w", err)
   }
   msgTypeField, ok := signedMsg.Field(SignedMessage_Type)
   if !ok {
      return nil, fmt.Errorf("SignedMessage is missing type field")
   }
   if msgTypeField.Numeric != SignedMessageType_LICENSE {
      return nil, fmt.Errorf("expected message type LICENSE, got %d", msgTypeField.Numeric)
   }
   licenseMsgField, ok := signedMsg.Field(SignedMessage_Msg)
   if !ok {
      return nil, fmt.Errorf("SignedMessage is missing message payload")
   }
   var licenseProto protobuf.Message
   if err := licenseProto.Parse(licenseMsgField.Bytes); err != nil {
      return nil, fmt.Errorf("failed to parse inner License message: %w", err)
   }
   license := &License{}
   keyIterator := licenseProto.Iterator(License_Key)
   for keyIterator.Next() {
      keyField := keyIterator.Field()
      if keyField == nil || keyField.Message == nil {
         continue
      }
      keyMsg := keyField.Message
      var newKey Key
      if idField, ok := keyMsg.Field(License_Key_Id); ok {
         newKey.ID = idField.Bytes
      }
      if valField, ok := keyMsg.Field(License_Key_Key); ok {
         newKey.Value = valField.Bytes
      }
      if typeField, ok := keyMsg.Field(License_Key_Type); ok {
         newKey.Type = keyTypeToString(typeField.Numeric)
      }
      license.Keys = append(license.Keys, newKey)
   }
   return license, nil
}
