package widevine

import (
   "fmt"

   "41.neocities.org/protobuf"
)

// SignedLicenseResponse is the top-level message received from the server.
type SignedLicenseResponse struct {
   Type       MessageType
   License    *License
   Signature  []byte
   SessionKey []byte
}

// ParseSignedLicenseResponse parses the raw bytes from a license server
// into a SignedLicenseResponse struct.
func ParseSignedLicenseResponse(data []byte) (*SignedLicenseResponse, error) {
   var msg protobuf.Message
   if err := msg.Parse(data); err != nil {
      return nil, fmt.Errorf("failed to parse top-level response protobuf: %w", err)
   }

   resp := &SignedLicenseResponse{}
   for _, field := range msg {
      switch field.Tag.FieldNum {
      case 1: // Type
         resp.Type = MessageType(field.Numeric)
      case 2: // Msg (which is the embedded License message)
         resp.License = &License{}
         if err := resp.License.ParseLicense(field.Message); err != nil {
            return nil, fmt.Errorf("failed to parse embedded license message: %w", err)
         }
      case 3: // Signature
         resp.Signature = field.Bytes
      case 4: // SessionKey (Corrected field number)
         resp.SessionKey = field.Bytes
      }
   }

   if resp.Type != MessageType_LICENSE_RESPONSE {
      return nil, fmt.Errorf("expected message type LICENSE_RESPONSE, but got %v", resp.Type)
   }

   return resp, nil
}
