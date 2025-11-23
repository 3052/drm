package widevine

import "41.neocities.org/protobuf"

// BuildLicenseRequest creates and serializes a Widevine LicenseRequest protobuf message.
// The psshData parameter should be the raw bytes from the PSSH box.
// Remove requestType from parameters
func BuildLicenseRequest(clientID []byte, psshData []byte) ([]byte, error) {
   psshDataField := protobuf.Bytes(1, psshData)
   widevinePsshData := protobuf.Embed(1, psshDataField)
   contentIdentification := protobuf.Embed(2, widevinePsshData)

   // Build the message
   message := protobuf.Message{
      protobuf.Bytes(1, clientID),
      contentIdentification,
      protobuf.Varint(3, 1), // Hardcode 1 (STREAMING) here
   }

   return message.Encode()
}
