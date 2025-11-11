package widevine

import (
   "41.neocities.org/protobuf"
   "fmt"
   "time"
)

// NewLicenseRequest creates a license request message payload.
// psshData is optional; if nil, you must provide keyIDs manually.
// If psshData is provided, its KeyIDs are used preferentially.
func NewLicenseRequest(psshData *PSSHData, clientInfo protobuf.Message, keyIDs [][]byte) (protobuf.Message, error) {
   var fields protobuf.Message

   var contentID []byte
   if psshData != nil {
      // Extract content_id from the PSSH data if present
      if field, ok := psshData.Data.Field(WidevineCencHeader_ContentId); ok {
         contentID = field.Bytes
      }
   }

   if len(contentID) > 0 {
      fields = append(fields, protobuf.NewBytes(LicenseRequest_ContentId, contentID))
   }

   fields = append(fields, protobuf.NewVarint(LicenseRequest_Type, LicenseRequestType_NEW))
   fields = append(fields, protobuf.NewVarint(LicenseRequest_RequestTime, uint64(time.Now().Unix())))

   // Use key IDs from PSSH if available, otherwise use provided ones.
   idsToUse := keyIDs
   if psshData != nil && len(psshData.KeyIDs) > 0 {
      idsToUse = psshData.KeyIDs
   }

   for _, kid := range idsToUse {
      fields = append(fields, protobuf.NewBytes(LicenseRequest_KeyId, kid))
   }

   // Add ClientInfo as an embedded message
   if clientInfo != nil {
      fields = append(fields, protobuf.NewMessage(LicenseRequest_ClientInfo, clientInfo...))
   }

   // Create LicenseRequest message
   licenseRequestMsg := protobuf.Message(fields)

   return licenseRequestMsg, nil
}

// BuildChallenge creates the full license challenge payload to be sent to the server.
// It wraps the licenseRequest message in a SignedMessage.
func BuildChallenge(licenseRequest protobuf.Message) ([]byte, error) {
   // A real implementation would sign the message and may include a session key.
   // For this example, we just wrap the message without a signature.

   encodedRequest, err := licenseRequest.Encode()
   if err != nil {
      return nil, fmt.Errorf("failed to encode license request: %w", err)
   }

   signedMessage := protobuf.Message{
      protobuf.NewVarint(SignedMessage_Type, SignedMessageType_LICENSE_REQUEST),
      protobuf.NewBytes(SignedMessage_Msg, encodedRequest),
      // protobuf.NewBytes(SignedMessage_Signature, signatureBytes), // Omitted
   }

   return signedMessage.Encode()
}
