package widevine

import "41.neocities.org/protobuf"

// LicenseRequest reflects the structure of the Widevine LicenseRequest protobuf.
type LicenseRequest struct {
   ClientID  *protobuf.Field
   ContentID *protobuf.Field
   Type      *protobuf.Field
}

// Build initializes a LicenseRequest with the given parameters.
// The psshData parameter should be the raw bytes from the PSSH box.
func (lr *LicenseRequest) Build(clientID []byte, psshData []byte, requestType int) {
   // For a minimal implementation, we create a ContentIdentification message
   // where the widevine_pssh_data field is populated.
   // The provided psshData is used for the nested pssh_data field.
   psshDataField := protobuf.Bytes(1, psshData)
   widevinePsshData := protobuf.Embed(1, psshDataField)
   contentIdentification := protobuf.Embed(2, widevinePsshData)

   lr.ClientID = protobuf.Bytes(1, clientID)
   lr.ContentID = contentIdentification
   lr.Type = protobuf.Varint(3, uint64(requestType))
}

// Encode serializes the LicenseRequest into the protobuf wire format.
func (lr *LicenseRequest) Encode() ([]byte, error) {
   message := protobuf.Message{lr.ClientID, lr.ContentID, lr.Type}
   return message.Encode()
}
