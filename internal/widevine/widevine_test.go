package widevine

import (
   "os"
   "testing"

   "41.neocities.org/protobuf"
)

func TestCreateWidevineLicenseRequest(t *testing.T) {
   // For this test to run, you must first create a private key file.
   // You can generate one using OpenSSL:
   // > openssl genrsa -out private_key.pem 2048
   privateKey, err := LoadPrivateKey("private_key.pem")
   if err != nil {
      // If the file doesn't exist, we can't proceed with a real signature.
      if os.IsNotExist(err) {
         t.Skip("skipping test: private_key.pem not found. Generate it with 'openssl genrsa -out private_key.pem 2048'")
      }
      t.Fatalf("Failed to load private key: %v", err)
   }

   // 1. Read the pre-existing ClientID from the specified file.
   clientIDBytes, err := os.ReadFile(`C:\Users\Steven\AppData\Local\L3\client_id.bin`)
   if err != nil {
      t.Fatalf("Failed to read client_id.bin: %v", err)
   }

   // 2. Create the innermost PSSHData message.
   psshData := &PSSHData{
      Algorithm: EncryptionMethod_AES_CTR,
      KeyIDs: [][]byte{
         {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
      },
      Provider:  "widevine_test",
      ContentID: []byte("my-awesome-content-id"),
   }

   // 3. Create the WidevinePsshData message.
   widevinePsshData := &WidevinePsshData{
      PSSHData: psshData, // Corrected typo here
   }

   // 4. Create the ContentIdentification message.
   contentIdentification := &ContentIdentification{
      WidevinePsshData: widevinePsshData,
      LicenseType:      LicenseType_STREAMING,
      RequestID:        []byte("some-request-id"),
   }

   // 5. Create the LicenseRequest message.
   licenseRequest := &LicenseRequest{
      ClientID:        clientIDBytes,
      ContentID:       contentIdentification,
      Type:            protobuf.WireBytes,
      KeyControlNonce: 12345,
   }

   // 6. Encode the LicenseRequest. This is the data that needs to be signed.
   licenseRequestBytes, err := licenseRequest.ToProto().Encode()
   if err != nil {
      t.Fatalf("Failed to encode LicenseRequest: %v", err)
   }

   // 7. Sign the encoded LicenseRequest using the loaded private key.
   signature, err := SignRequestData(privateKey, licenseRequestBytes)
   if err != nil {
      t.Fatalf("Failed to sign license request data: %v", err)
   }

   // 8. Create the SignedLicenseRequest message with the real signature.
   signedLicenseRequest := &SignedLicenseRequest{
      Type:               protobuf.WireBytes,
      Msg:                licenseRequestBytes,
      Signature:          signature,
      SessionKey:         []byte("a-real-session-key-would-go-here"),
      SignatureAlgorithm: SignatureAlgorithm_RSASSA_PSS_SHA1,
   }

   // 9. Encode the final SignedLicenseRequest.
   finalRequestBytes, err := signedLicenseRequest.ToProto().Encode()
   if err != nil {
      t.Fatalf("Failed to encode SignedLicenseRequest: %v", err)
   }

   t.Logf("Successfully created and signed Widevine license request.")
   t.Logf("Signature (hex): %x", signature)
   t.Logf("Encoded Final Request (hex): %x", finalRequestBytes)
}
