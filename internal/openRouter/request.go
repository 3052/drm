package widevine

import (
   "41.neocities.org/protobuf"
   "fmt"
   "time"
)

// NewLicenseRequest creates a license request message payload directly from raw WidevineCencHeader protobuf bytes.
// This is an efficient method that avoids decoding the header into a struct and re-encoding it.
// - headerBytes: Raw bytes of the WidevineCencHeader protobuf message.
// - clientInfoBytes: Pre-encoded ClientInfo protobuf message.
func NewLicenseRequest(headerBytes []byte, clientInfoBytes []byte) (protobuf.Message, error) {
   // Perform a low-level parse of the header to access its fields.
   var headerMsg protobuf.Message
   if err := headerMsg.Parse(headerBytes); err != nil {
      return nil, fmt.Errorf("failed to parse headerBytes: %w", err)
   }

   var requestFields protobuf.Message

   // Find the ContentId field in the header and add it to the request
   // with the correct field tag for a LicenseRequest.
   if field, ok := headerMsg.Field(WidevineCencHeader_ContentId); ok {
      requestFields = append(requestFields, protobuf.NewBytes(LicenseRequest_ContentId, field.Bytes))
   }

   // Iterate over all KeyId fields in the header and add them to the request
   // with the correct field tag.
   keyIDIterator := headerMsg.Iterator(WidevineCencHeader_KeyId)
   for keyIDIterator.Next() {
      field := keyIDIterator.Field()
      if field != nil {
         requestFields = append(requestFields, protobuf.NewBytes(LicenseRequest_KeyId, field.Bytes))
      }
   }

   // Add the other standard fields for a license request.
   requestFields = append(requestFields, protobuf.NewVarint(LicenseRequest_Type, LicenseRequestType_NEW))
   requestFields = append(requestFields, protobuf.NewVarint(LicenseRequest_RequestTime, uint64(time.Now().Unix())))

   // Add the client info sub-message.
   if len(clientInfoBytes) > 0 {
      var clientInfoMsg protobuf.Message
      if err := clientInfoMsg.Parse(clientInfoBytes); err != nil {
         return nil, fmt.Errorf("failed to parse clientInfoBytes as a valid protobuf message: %w", err)
      }
      requestFields = append(requestFields, protobuf.NewMessage(LicenseRequest_ClientInfo, clientInfoMsg...))
   }

   return protobuf.Message(requestFields), nil
}

// BuildChallenge wraps the license request in a SignedMessage to create the final challenge.
func BuildChallenge(licenseRequest protobuf.Message) ([]byte, error) {
   encodedRequest, err := licenseRequest.Encode()
   if err != nil {
      return nil, fmt.Errorf("failed to encode license request: %w", err)
   }

   signedMessage := protobuf.Message{
      protobuf.NewVarint(SignedMessage_Type, SignedMessageType_LICENSE_REQUEST),
      protobuf.NewBytes(SignedMessage_Msg, encodedRequest),
   }

   return signedMessage.Encode()
}
