package widevine

import (
   "bytes"
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
      PSSHData: psshData,
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
      Type:            RequestType_NEW,
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
      Type:               MessageType_LICENSE_REQUEST,
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

func TestParseWidevineLicenseResponse(t *testing.T) {
   // 1. Construct a mock License message.
   // This simulates the data a license server would create.
   mockKeyID := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
   mockContentKey := []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}

   licenseMsg := protobuf.Message{
      // A License_Key
      protobuf.NewMessage(1,
         protobuf.NewBytes(1, mockKeyID),
         protobuf.NewVarint(2, uint64(KeyType_CONTENT)),
         protobuf.NewBytes(3, mockContentKey),
      ),
      // A Policy
      protobuf.NewMessage(2,
         protobuf.NewVarint(1, 1),     // CanPlay = true
         protobuf.NewVarint(3, 1),     // CanRenew = true
         protobuf.NewVarint(6, 86400), // LicenseDurationSeconds = 24 hours
      ),
   }
   licenseBytes, err := licenseMsg.Encode()
   if err != nil {
      t.Fatalf("failed to encode mock license: %v", err)
   }

   // 2. Construct a mock SignedLicenseResponse containing the license.
   mockSignature := []byte("this-is-a-mock-server-signature")
   signedResponseMsg := protobuf.Message{
      protobuf.NewVarint(1, uint64(MessageType_LICENSE_RESPONSE)),
      protobuf.NewBytes(2, licenseBytes),
      protobuf.NewBytes(3, mockSignature),
   }
   signedResponseBytes, err := signedResponseMsg.Encode()
   if err != nil {
      t.Fatalf("failed to encode mock signed response: %v", err)
   }

   // 3. Parse the mock response bytes.
   parsedResponse, err := ParseSignedLicenseResponse(signedResponseBytes)
   if err != nil {
      t.Fatalf("ParseSignedLicenseResponse failed: %v", err)
   }

   // 4. Verify the contents of the parsed response.
   if parsedResponse.Type != MessageType_LICENSE_RESPONSE {
      t.Errorf("expected type %v, got %v", MessageType_LICENSE_RESPONSE, parsedResponse.Type)
   }
   if !bytes.Equal(parsedResponse.Signature, mockSignature) {
      t.Errorf("signature mismatch")
   }
   if parsedResponse.License == nil {
      t.Fatal("parsed license is nil")
   }
   if len(parsedResponse.License.Keys) != 1 {
      t.Fatalf("expected 1 key, got %d", len(parsedResponse.License.Keys))
   }

   key := parsedResponse.License.Keys[0]
   if !bytes.Equal(key.ID, mockKeyID) {
      t.Errorf("key ID mismatch")
   }
   if !bytes.Equal(key.Key, mockContentKey) {
      t.Errorf("content key mismatch")
   }
   if key.Type != KeyType_CONTENT {
      t.Errorf("key type mismatch")
   }

   policy := parsedResponse.License.Policy
   if policy == nil {
      t.Fatal("parsed policy is nil")
   }
   if !policy.CanPlay {
      t.Errorf("expected CanPlay to be true")
   }
   if policy.LicenseDurationSeconds != 86400 {
      t.Errorf("expected LicenseDurationSeconds to be 86400, got %d", policy.LicenseDurationSeconds)
   }

   t.Log("Successfully parsed mock license response.")
}
