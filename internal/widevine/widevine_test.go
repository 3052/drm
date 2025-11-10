package widevine

import (
   "testing"

   "41.neocities.org/protobuf"
)

func TestCreateWidevineLicenseRequest(t *testing.T) {
   // 1. Create the ClientIdentification message.
   clientCapabilities := &ClientCapabilities{
      ClientRobustness: "SW_SECURE_CRYPTO",
   }
   clientIdentification := &ClientIdentification{
      Token:              []byte("some-client-token"),
      ClientCapabilities: clientCapabilities,
   }

   // 2. Create the ContentIdentification message.
   contentIdentification := &ContentIdentification{
      PSSH:        []byte{0x00, 0x00, 0x00, 0x3c, 0x70, 0x73, 0x73, 0x68}, // Example PSSH box
      LicenseType: LicenseType_STREAMING,
      RequestID:   []byte("some-request-id"),
   }

   // 3. Create the LicenseRequest message.
   licenseRequest := &LicenseRequest{
      ClientID:        clientIdentification,
      ContentID:       contentIdentification,
      Type:            protobuf.WireBytes, // This seems to be consistently WireBytes
      KeyControlNonce: 12345,
   }

   // 4. Encode the LicenseRequest.
   licenseRequestBytes, err := licenseRequest.ToProto().Encode()
   if err != nil {
      t.Fatalf("Failed to encode LicenseRequest: %v", err)
   }

   // 5. Create the SignedLicenseRequest message.
   // In a real scenario, you would generate a real signature and session key.
   signedLicenseRequest := &SignedLicenseRequest{
      Type:               protobuf.WireBytes,
      Msg:                licenseRequestBytes,
      Signature:          []byte("a-real-signature-would-go-here"),
      SessionKey:         []byte("a-real-session-key-would-go-here"),
      SignatureAlgorithm: SignatureAlgorithm_RSASSA_PSS_SHA1,
   }

   // 6. Encode the SignedLicenseRequest.
   finalRequestBytes, err := signedLicenseRequest.ToProto().Encode()
   if err != nil {
      t.Fatalf("Failed to encode SignedLicenseRequest: %v", err)
   }

   t.Logf("Successfully created and encoded Widevine license request.")
   t.Logf("Encoded Request (hex): %x", finalRequestBytes)
}
