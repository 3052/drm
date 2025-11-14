package widevine

import "41.neocities.org/protobuf"

// BuildPsshData serializes the key IDs and content ID into the protobuf wire format
// for a Widevine PSSH box body. The resulting byte slice can be used as the
// 'psshData' parameter for the LicenseRequest.Build method.
func BuildPsshData(keyIDs [][]byte, contentID []byte) ([]byte, error) {
   var message protobuf.Message

   // Add all KeyIDs. Field number is 2.
   for _, keyID := range keyIDs {
      if keyID != nil {
         field := protobuf.Bytes(2, keyID)
         message = append(message, field)
      }
   }

   // Add ContentID if it exists. Field number is 4.
   if len(contentID) > 0 {
      field := protobuf.Bytes(4, contentID)
      message = append(message, field)
   }

   return message.Encode()
}
