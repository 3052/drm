package widevine

import "41.neocities.org/protobuf"

// BuildLicenseRequest creates and serializes a Widevine LicenseRequest protobuf message.
// It is a method on PsshData, which is marshaled to populate the pssh_data field.
// It defaults to RequestType 1 (STREAMING).
func (p *PsshData) BuildLicenseRequest(clientID []byte) ([]byte, error) {
   // 1. Serialize the PsshData struct
   psshBytes, err := p.Marshal()
   if err != nil {
      return nil, err
   }

   // 2. Build the ContentIdentification structure.
   // Structure: ContentIdentification(2) -> WidevinePsshData(1) -> [Raw Bytes]
   // Note: We maintain the nesting structure from the original file implementation.
   psshDataField := protobuf.Bytes(1, psshBytes)
   widevinePsshData := protobuf.Embed(1, psshDataField)
   contentIdentification := protobuf.Embed(2, widevinePsshData)

   // 3. Build the top-level LicenseRequest message.
   message := protobuf.Message{
      protobuf.Bytes(1, clientID),
      contentIdentification,
      protobuf.Varint(3, 1), // Hardcoded 1 = STREAMING
   }

   return message.Encode()
}
