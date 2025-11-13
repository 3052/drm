package widevine

import (
   "bytes"
   "crypto"
   "crypto/rand"
   "crypto/rsa"
   "crypto/sha1"
   "os"
   "testing"

   "41.neocities.org/protobuf"
)

// helper function to load the private key and skip tests if it's not present.
func loadTestKey(t *testing.T) *rsa.PrivateKey {
   t.Helper()
   keyPath := "private_key.pem"
   pemBytes, err := os.ReadFile(keyPath)
   if err != nil {
      if os.IsNotExist(err) {
         t.Skipf("skipping test: test key file not found at %s", keyPath)
      }
      t.Fatalf("Failed to read private key file: %v", err)
   }

   privateKey, err := ParsePrivateKey(pemBytes)
   if err != nil {
      t.Fatalf("Failed to parse private key from %s: %v", keyPath, err)
   }
   return privateKey
}

// TestParseLicenseResponse_License tests parsing a valid license response.
func TestParseLicenseResponse_License(t *testing.T) {
   privateKey := loadTestKey(t)
   publicKey := &privateKey.PublicKey

   plaintextContentKey := []byte{0xDE, 0xC0, 0xAD, 0xED, 0xDE, 0xC0, 0xAD, 0xED}
   encryptedContentKey, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, plaintextContentKey, nil)

   // Build the KeyContainer message as a slice of fields
   keyContainerMessage := protobuf.Message{
      protobuf.NewBytes(3, encryptedContentKey), // Field 3: key
   }
   keyContainerBytes, _ := keyContainerMessage.Encode()

   // Build the inner License message as a slice of fields
   licenseMessage := protobuf.Message{
      protobuf.NewBytes(3, keyContainerBytes), // Field 3: key (which is our KeyContainer)
   }
   licenseBytes, _ := licenseMessage.Encode()

   // Build the outer SignedMessage
   signedResponse := protobuf.Message{
      protobuf.NewVarint(1, 2),                 // type = LICENSE
      protobuf.NewBytes(2, licenseBytes),       // msg = encoded License message
      protobuf.NewBytes(3, []byte{0x01, 0x02}), // dummy signature
   }
   signedBytes, _ := signedResponse.Encode()

   // Parse the response
   parsed, err := ParseLicenseResponse(signedBytes, privateKey)
   if err != nil {
      t.Fatalf("ParseLicenseResponse failed: %v", err)
   }

   // Verify the result
   if parsed.Error != nil {
      t.Fatal("Expected a License, but got an Error")
   }
   if parsed.License == nil {
      t.Fatal("Expected a License, but got nil")
   }
   if len(parsed.License.Keys) != 1 {
      t.Fatalf("Expected 1 key, got %d", len(parsed.License.Keys))
   }
   if !bytes.Equal(parsed.License.Keys[0].Key, plaintextContentKey) {
      t.Errorf("Decrypted key mismatch")
   }
}

// TestParseLicenseResponse_Error tests parsing a valid error response.
func TestParseLicenseResponse_Error(t *testing.T) {
   privateKey := loadTestKey(t)
   expectedCode := uint64(1) // INVALID_DRM_DEVICE_CERTIFICATE

   // Build the inner LicenseError message
   errorMsg := protobuf.Message{protobuf.NewVarint(1, expectedCode)}
   errorBytes, _ := errorMsg.Encode()

   // Build the outer SignedMessage
   signedResponse := protobuf.Message{
      protobuf.NewVarint(1, 3),                 // type = ERROR_RESPONSE
      protobuf.NewBytes(2, errorBytes),         // msg = encoded LicenseError message
      protobuf.NewBytes(3, []byte{0x01, 0x02}), // dummy signature
   }
   signedBytes, _ := signedResponse.Encode()

   // Parse the response
   parsed, err := ParseLicenseResponse(signedBytes, privateKey)
   if err != nil {
      t.Fatalf("ParseLicenseResponse failed: %v", err)
   }

   // Verify the result
   if parsed.License != nil {
      t.Fatal("Expected an Error, but got a License")
   }
   if parsed.Error == nil {
      t.Fatal("Expected an Error, but got nil")
   }
   if parsed.Error.ErrorCode.Numeric != expectedCode {
      t.Errorf("Expected error code %d, got %d", expectedCode, parsed.Error.ErrorCode.Numeric)
   }
}

// verifySignature is a helper function to verify a signature made with rsa.SignPSS.
func verifySignature(t *testing.T, publicKey *rsa.PublicKey, msg, signature []byte) {
   t.Helper()
   hash := sha1.New()
   hash.Write(msg)
   hashed := hash.Sum(nil)

   opts := &rsa.PSSOptions{
      SaltLength: rsa.PSSSaltLengthEqualsHash,
      Hash:       crypto.SHA1,
   }

   err := rsa.VerifyPSS(publicKey, crypto.SHA1, hashed, signature, opts)
   if err != nil {
      t.Errorf("Signature verification failed with PSS: %v", err)
   }
}

// TestSignedMessageCreation checks that the session key is correctly generated.
func TestSignedMessageCreation(t *testing.T) {
   privateKey := loadTestKey(t)
   req := NewLicenseRequest([]byte{1}, []byte{2}, 1)
   reqBytes, err := req.Encode()
   if err != nil {
      t.Fatalf("Failed to encode request: %v", err)
   }
   signedMsg, err := NewSignedRequest(privateKey, reqBytes)
   if err != nil {
      t.Fatalf("Failed to create signed request: %v", err)
   }
   if signedMsg.SessionKey == nil || len(signedMsg.SessionKey.Bytes) == 0 {
      t.Fatal("SessionKey was not automatically generated in the signed request")
   }
   verifySignature(t, &privateKey.PublicKey, signedMsg.Msg.Bytes, signedMsg.Signature.Bytes)
}

// TestEncodeLicenseRequest verifies that a new LicenseRequest is encoded correctly.
func TestEncodeLicenseRequest(t *testing.T) {
   clientID := []byte{0xCA, 0xFE, 0xBA, 0xBE}
   psshData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
   requestType := 1
   req := NewLicenseRequest(clientID, psshData, requestType)
   encoded, err := req.Encode()
   if err != nil {
      t.Fatalf("Failed to encode LicenseRequest: %v", err)
   }
   expected := []byte{0x0a, 0x04, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x08, 0x0a, 0x06, 0x0a, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x18, 0x01}
   if !bytes.Equal(encoded, expected) {
      t.Errorf("Encoded LicenseRequest does not match expected bytes.\nGot:  %x\nWant: %x", encoded, expected)
   }
}
