package widevine

import (
   "41.neocities.org/protobuf"
)

// LicenseRequest reflects the structure of the Widevine LicenseRequest protobuf.
type LicenseRequest struct {
   ClientID  *protobuf.Field
   ContentID *protobuf.Field
   Type      *protobuf.Field
}

// NewLicenseRequest creates and initializes a new LicenseRequest.
// The psshData parameter should be the raw bytes from the PSSH box.
func NewLicenseRequest(clientID []byte, psshData []byte, requestType int) *LicenseRequest {
   // For a minimal implementation, we create a ContentIdentification message
   // where the widevine_pssh_data field is populated.
   // The provided psshData is used for the nested pssh_data field.
   psshDataField := protobuf.NewBytes(1, psshData)
   widevinePsshData := protobuf.NewMessage(1, psshDataField)
   contentIdentification := protobuf.NewMessage(2, widevinePsshData)

   return &LicenseRequest{
      ClientID:  protobuf.NewBytes(1, clientID),
      ContentID: contentIdentification,
      Type:      protobuf.NewVarint(3, uint64(requestType)),
   }
}

// Encode serializes the LicenseRequest into the protobuf wire format.
func (lr *LicenseRequest) Encode() ([]byte, error) {
   message := protobuf.Message{lr.ClientID, lr.ContentID, lr.Type}
   return message.Encode()
}
