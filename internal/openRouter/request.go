package widevine

import (
   "41.neocities.org/protobuf"
   "fmt"
   "time"
)

// BuildChallenge creates the full license challenge payload to be sent to the server.
// It constructs a LicenseRequest from the provided header and client info,
// wraps it in a SignedMessage, and returns the final encoded bytes in a single step.
// - headerBytes: Raw bytes of the WidevineCencHeader protobuf message.
// - clientInfoBytes: Pre-encoded ClientInfo protobuf message.
func BuildChallenge(headerBytes []byte, clientInfoBytes []byte) ([]byte, error) {
   // Parse the header bytes to access its fields.
   var headerMsg protobuf.Message
   if err := headerMsg.Parse(headerBytes); err != nil {
      return nil, fmt.Errorf("failed to parse headerBytes: %w", err)
   }

   // Build the inner LicenseRequest message fields.
   var requestFields protobuf.Message

   // Copy ContentId and KeyId(s) from the header to the request,
   // assigning the correct field tags for a LicenseRequest.
   if field, ok := headerMsg.Field(WidevineCencHeader_ContentId); ok {
      requestFields = append(requestFields, protobuf.NewBytes(LicenseRequest_ContentId, field.Bytes))
   }
   keyIDIterator := headerMsg.Iterator(WidevineCencHeader_KeyId)
   for keyIDIterator.Next() {
      field := keyIDIterator.Field()
      if field != nil {
         requestFields = append(requestFields, protobuf.NewBytes(LicenseRequest_KeyId, field.Bytes))
      }
   }

   // Add the other standard request fields.
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

   // Encode the inner request.
   encodedRequest, err := requestFields.Encode()
   if err != nil {
      return nil, fmt.Errorf("failed to encode internal license request: %w", err)
   }

   // Wrap the encoded request in the final SignedMessage.
   signedMessage := protobuf.Message{
      protobuf.NewVarint(SignedMessage_Type, SignedMessageType_LICENSE_REQUEST),
      protobuf.NewBytes(SignedMessage_Msg, encodedRequest),
   }

   return signedMessage.Encode()
}
