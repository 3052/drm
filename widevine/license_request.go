package widevine

import "41.neocities.org/protobuf"

// BuildLicenseRequest creates and serializes a Widevine LicenseRequest protobuf message.
// The psshData parameter should be the raw bytes from the PSSH box.
func BuildLicenseRequest(clientID []byte, psshData []byte, requestType int) ([]byte, error) {
   // For a minimal implementation, we create a ContentIdentification message
   // where the widevine_pssh_data field is populated.
   // The provided psshData is used for the nested pssh_data field.
   psshDataField := protobuf.Bytes(1, psshData)
   widevinePsshData := protobuf.Embed(1, psshDataField)
   contentIdentification := protobuf.Embed(2, widevinePsshData)

   // Build the message with its fields.
   message := protobuf.Message{
      protobuf.Bytes(1, clientID),
      contentIdentification,
      protobuf.Varint(3, uint64(requestType)),
   }

   return message.Encode()
}
