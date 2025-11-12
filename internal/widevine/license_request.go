package widevine

import (
   "41.neocities.org/protobuf"
)

// LicenseRequest reflects the structure of the Widevine LicenseRequest protobuf.
type LicenseRequest struct {
   ContentID *protobuf.Field
   Type      *protobuf.Field
}

// NewLicenseRequest creates and initializes a new LicenseRequest.
func NewLicenseRequest(contentID []byte, requestType int) *LicenseRequest {
   // For a minimal implementation, we'll create a simple ContentIdentification message
   // with just the `widevine_pssh_data` field populated.
   psshData := protobuf.NewBytes(1, contentID)
   widevinePsshData := protobuf.NewMessage(1, psshData)
   contentIdentification := protobuf.NewMessage(2, widevinePsshData)

   return &LicenseRequest{
      ContentID: contentIdentification,
      Type:      protobuf.NewVarint(3, uint64(requestType)),
   }
}

// Encode serializes the LicenseRequest into the protobuf wire format.
func (lr *LicenseRequest) Encode() ([]byte, error) {
   message := protobuf.Message{lr.ContentID, lr.Type}
   return message.Encode()
}
