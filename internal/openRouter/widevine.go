package widevine

import (
   "41.neocities.org/protobuf"
   "fmt"
)

// Widevine System ID
var SystemID = []byte{0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed}

// --- Field Numbers ---

const (
   // WidevineCencHeader fields
   WidevineCencHeader_Algorithm uint32 = 1
   WidevineCencHeader_KeyId     uint32 = 2
   WidevineCencHeader_Provider  uint32 = 3
   WidevineCencHeader_ContentId uint32 = 4
   WidevineCencHeader_TrackType uint32 = 8
   WidevineCencHeader_Policy    uint32 = 9

   // SignedMessage fields
   SignedMessage_Type       uint32 = 1
   SignedMessage_Msg        uint32 = 2
   SignedMessage_Signature  uint32 = 3
   SignedMessage_SessionKey uint32 = 4

   // LicenseRequest fields
   LicenseRequest_ContentId   uint32 = 1
   LicenseRequest_Type        uint32 = 2
   LicenseRequest_RequestTime uint32 = 3
   LicenseRequest_KeyId       uint32 = 4
   LicenseRequest_DRMSession  uint32 = 5
   LicenseRequest_ClientInfo  uint32 = 7

   // ClientInfo fields
   ClientInfo_ClientInfoToken    uint32 = 1
   ClientInfo_WidevinecdmVersion uint32 = 2
   ClientInfo_Os                 uint32 = 3
   ClientInfo_Arch               uint32 = 4
   ClientInfo_DeviceModel        uint32 = 5

   // License fields
   License_Id     uint32 = 1
   License_Policy uint32 = 2
   License_Key    uint32 = 3

   // License_Key fields
   License_Key_Id   uint32 = 1
   License_Key_Key  uint32 = 3
   License_Key_Type uint32 = 4
)

// --- Enums ---

const (
   LicenseRequestType_NEW     uint64 = 1
   LicenseRequestType_RENEWAL uint64 = 2

   SignedMessageType_LICENSE_REQUEST uint64 = 1
   SignedMessageType_LICENSE         uint64 = 2

   Algorithm_UNENCRYPTED uint64 = 0
   Algorithm_AESCTR      uint64 = 1

   KeyType_OPERATOR_SESSION uint64 = 1
   KeyType_ENCRYPTION       uint64 = 2
   KeyType_SIGNING          uint64 = 3
   KeyType_CONTENT          uint64 = 4
)

// License represents the data parsed from a Widevine license response.
type License struct {
   Keys []Key
   // Other fields like Policy can be added here
}

// Key represents a single decryption key from the license.
type Key struct {
   ID    []byte
   Value []byte
   Type  string
}

// keyTypeToString maps the key type enum to a human-readable string.
func keyTypeToString(keyType uint64) string {
   switch keyType {
   case KeyType_OPERATOR_SESSION:
      return "OPERATOR_SESSION"
   case KeyType_ENCRYPTION:
      return "ENCRYPTION"
   case KeyType_SIGNING:
      return "SIGNING"
   case KeyType_CONTENT:
      return "CONTENT"
   default:
      return "UNKNOWN"
   }
}

// ParseLicenseResponse parses the raw license response from the Widevine server.
func ParseLicenseResponse(responseBytes []byte) (*License, error) {
   // First, parse the outer SignedMessage
   var signedMsg protobuf.Message
   if err := signedMsg.Parse(responseBytes); err != nil {
      return nil, fmt.Errorf("failed to parse SignedMessage: %w", err)
   }

   // Verify the type is LICENSE
   msgTypeField, ok := signedMsg.Field(SignedMessage_Type)
   if !ok {
      return nil, fmt.Errorf("SignedMessage is missing type field")
   }
   if msgTypeField.Numeric != SignedMessageType_LICENSE {
      return nil, fmt.Errorf("expected message type LICENSE, got %d", msgTypeField.Numeric)
   }

   // Get the inner message payload (the License)
   licenseMsgField, ok := signedMsg.Field(SignedMessage_Msg)
   if !ok {
      return nil, fmt.Errorf("SignedMessage is missing message payload")
   }

   // Parse the inner License message
   var licenseProto protobuf.Message
   if err := licenseProto.Parse(licenseMsgField.Bytes); err != nil {
      return nil, fmt.Errorf("failed to parse inner License message: %w", err)
   }

   // Convert the protobuf message to our user-friendly License struct
   license := &License{}

   // Iterate over all key fields (field number 3)
   keyIterator := licenseProto.Iterator(License_Key)
   for keyIterator.Next() {
      keyField := keyIterator.Field()
      if keyField != nil && keyField.Message != nil {
         // Each key is an embedded message
         keyMsg := keyField.Message

         var newKey Key

         // Extract Key ID
         if idField, ok := keyMsg.Field(License_Key_Id); ok {
            newKey.ID = idField.Bytes
         }

         // Extract Key Value
         if valField, ok := keyMsg.Field(License_Key_Key); ok {
            newKey.Value = valField.Bytes
         }

         // Extract Key Type
         if typeField, ok := keyMsg.Field(License_Key_Type); ok {
            newKey.Type = keyTypeToString(typeField.Numeric)
         }

         license.Keys = append(license.Keys, newKey)
      }
   }

   return license, nil
}
