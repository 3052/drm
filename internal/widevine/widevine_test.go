package widevine

import (
   "bytes"
   "crypto"
   "crypto/rand"
   "crypto/rsa"
   "crypto/sha1"
   "os"
   "testing"
)

// helper function to load the private key and skip tests if it's not present.
func loadTestKey(t *testing.T) *rsa.PrivateKey {
   t.Helper() // Marks this as a test helper function.
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

// TestSignedMessageCreation checks that the session key (public key) is correctly generated.
func TestSignedMessageCreation(t *testing.T) {
   privateKey := loadTestKey(t) // This will skip the test if key is not found

   req := NewLicenseRequest([]byte{1}, []byte{2}, 1)
   reqBytes, err := req.Encode()
   if err != nil {
      t.Fatalf("Failed to encode request: %v", err)
   }

   signedMsg, err := NewSignedRequest(privateKey, reqBytes)
   if err != nil {
      t.Fatalf("Failed to create signed request: %v", err)
   }

   // Verify that the session key was added
   if signedMsg.SessionKey == nil || len(signedMsg.SessionKey.Bytes) == 0 {
      t.Fatal("SessionKey was not automatically generated in the signed request")
   }

   // Verify the signature for good measure
   verifySignature(t, &privateKey.PublicKey, signedMsg.Msg.Bytes, signedMsg.Signature.Bytes)
}

// TestLicenseKeyDecryption tests the full flow of parsing a license and decrypting the key.
func TestLicenseKeyDecryption(t *testing.T) {
   privateKey := loadTestKey(t) // This will skip the test if key is not found
   publicKey := &privateKey.PublicKey

   // 2. Define a plaintext content key
   plaintextContentKey := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

   // 3. Simulate the server: Encrypt the content key with the public key
   encryptedContentKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, plaintextContentKey, nil)
   if err != nil {
      t.Fatalf("Failed to simulate server key encryption: %v", err)
   }

   // 4. Manually construct a protobuf License message containing the encrypted key
   keyContainerBytes := []byte{
      /* Field 3 (key) */ 0x1a,
      /* Length */ byte(len(encryptedContentKey)),
   }
   keyContainerBytes = append(keyContainerBytes, encryptedContentKey...)

   licenseBytes := []byte{
      /* Field 3 (key) - repeated */ 0x1a,
      /* Length of KeyContainer */ byte(len(keyContainerBytes)),
   }
   licenseBytes = append(licenseBytes, keyContainerBytes...)

   // 5. Parse the license and decrypt the key using the private key
   license, err := ParseLicense(licenseBytes, privateKey)
   if err != nil {
      t.Fatalf("Failed to parse license: %v", err)
   }

   // 6. Verify the result
   if len(license.Keys) != 1 {
      t.Fatalf("Expected 1 key container, got %d", len(license.Keys))
   }

   decryptedKey := license.Keys[0].Key
   if !bytes.Equal(decryptedKey, plaintextContentKey) {
      t.Errorf("Decrypted key does not match original plaintext key.\nGot:  %x\nWant: %x", decryptedKey, plaintextContentKey)
   }
}

// verifySignature is a helper function to verify a signature.
func verifySignature(t *testing.T, publicKey *rsa.PublicKey, msg, signature []byte) {
   t.Helper()
   msgHash := sha1.New()
   msgHash.Write(msg)
   hashed := msgHash.Sum(nil)
   err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hashed, signature)
   if err != nil {
      t.Errorf("Signature verification failed: %v", err)
   }
}

// TestEncodeLicenseRequest verifies that a new LicenseRequest is encoded correctly.
func TestEncodeLicenseRequest(t *testing.T) {
   clientID := []byte{0xCA, 0xFE, 0xBA, 0xBE}
   psshData := []byte{0xDE, 0xAD, 0xBE, 0xEF} // declared here
   requestType := 1                           // NEW

   req := NewLicenseRequest(clientID, psshData, requestType) // Corrected: pshData -> psshData
   encoded, err := req.Encode()
   if err != nil {
      t.Fatalf("Failed to encode LicenseRequest: %v", err)
   }

   expected := []byte{
      0x0a, 0x04, 0xca, 0xfe, 0xba, 0xbe,
      0x12, 0x08, 0x0a, 0x06, 0x0a, 0x04, 0xde, 0xad, 0xbe, 0xef,
      0x18, 0x01,
   }

   if !bytes.Equal(encoded, expected) {
      t.Errorf("Encoded LicenseRequest does not match expected bytes.\nGot:  %x\nWant: %x", encoded, expected)
   }
}

// TestParseLicenseError verifies that a LicenseError message is parsed correctly.
func TestParseLicenseError(t *testing.T) {
   errorBytes := []byte{0x08, 0x01}
   expectedErrorCode := uint64(1)

   licenseError, err := ParseLicenseError(errorBytes)
   if err != nil {
      t.Fatalf("Failed to parse LicenseError: %v", err)
   }

   if licenseError.ErrorCode == nil {
      t.Fatal("Parsed license error code is nil")
   }
   if licenseError.ErrorCode.Numeric != expectedErrorCode {
      t.Errorf("Expected error code %d, got %d", expectedErrorCode, licenseError.ErrorCode.Numeric)
   }
}
