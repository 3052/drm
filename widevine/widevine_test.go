package widevine

import (
   "bytes"
   "crypto"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rand"
   "crypto/rsa"
   "crypto/sha1"
   "encoding/binary"
   "os"
   "testing"

   "41.neocities.org/protobuf"
   "github.com/emmansun/gmsm/cbcmac"
   "github.com/emmansun/gmsm/padding"
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

func TestParsedResponse_GetKey(t *testing.T) {
   // 1. Create a dummy response with multiple keys
   id1 := []byte{0x01, 0x01, 0x01, 0x01}
   key1 := []byte{0xAA, 0xAA, 0xAA, 0xAA}
   id2 := []byte{0x02, 0x02, 0x02, 0x02}
   key2 := []byte{0xBB, 0xBB, 0xBB, 0xBB}
   nonexistentID := []byte{0xFF, 0xFF, 0xFF, 0xFF}

   response := &ParsedResponse{
      Keys: []*KeyContainer{
         {ID: id1, Key: key1},
         {ID: id2, Key: key2},
      },
   }

   // 2. Test finding an existing key
   foundKey, ok := response.GetKey(id2)
   if !ok {
      t.Fatal("Expected to find key with id2, but did not")
   }
   if !bytes.Equal(foundKey, key2) {
      t.Errorf("Returned key for id2 is incorrect. Got %x, want %x", foundKey, key2)
   }

   // 3. Test finding another existing key
   foundKey, ok = response.GetKey(id1)
   if !ok {
      t.Fatal("Expected to find key with id1, but did not")
   }
   if !bytes.Equal(foundKey, key1) {
      t.Errorf("Returned key for id1 is incorrect. Got %x, want %x", foundKey, key1)
   }

   // 4. Test searching for a key that does not exist
   foundKey, ok = response.GetKey(nonexistentID)
   if ok {
      t.Error("Expected not to find a key, but did")
   }
   if foundKey != nil {
      t.Errorf("Expected nil key for nonexistent ID, but got %x", foundKey)
   }

   // 5. Test on a response with no keys
   emptyResponse := &ParsedResponse{Keys: nil}
   _, ok = emptyResponse.GetKey(id1)
   if ok {
      t.Error("Expected not to find a key in an empty response, but did")
   }
}

// TestParseLicenseResponse_EndToEndDecryption tests the full decryption flow.
func TestParseLicenseResponse_EndToEndDecryption(t *testing.T) {
   privateKey := loadTestKey(t)
   publicKey := &privateKey.PublicKey

   // == Step 1: Define original data ==
   plaintextContentKey := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}
   contentKeyIV := []byte{0xA1, 0xB2, 0xC3, 0xD4, 0xA1, 0xB2, 0xC3, 0xD4, 0xA1, 0xB2, 0xC3, 0xD4, 0xA1, 0xB2, 0xC3, 0xD4}
   dummyOriginalRequest := []byte{0xAA, 0xBB, 0xCC}

   // == Step 2: Simulate Server-Side Logic ==
   sessionKey := make([]byte, 16) // AES-128
   rand.Read(sessionKey)
   encryptedSessionKey, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, sessionKey, nil)
   cmacCipher, _ := aes.NewCipher(sessionKey)

   var kdfInput []byte
   kdfInput = append(kdfInput, 0x01)
   kdfInput = append(kdfInput, []byte(kWrappingKeyLabel)...)
   kdfInput = append(kdfInput, 0x00)
   kdfInput = append(kdfInput, dummyOriginalRequest...)
   sizeBytes := make([]byte, 4)
   binary.BigEndian.PutUint32(sizeBytes, kWrappingKeySizeBits)
   kdfInput = append(kdfInput, sizeBytes...)

   cmac := cbcmac.NewCMAC(cmacCipher, 16)
   derivedKey := cmac.MAC(kdfInput)

   contentCipher, _ := aes.NewCipher(derivedKey)
   pkcs7 := padding.NewPKCS7Padding(aes.BlockSize)
   paddedKey := pkcs7.Pad(plaintextContentKey)
   encryptedKey := make([]byte, len(paddedKey))
   encrypter := cipher.NewCBCEncrypter(contentCipher, contentKeyIV)
   encrypter.CryptBlocks(encryptedKey, paddedKey)

   // == Step 3: Build the Protobuf Response ==
   keyContainerMessage := protobuf.Message{
      protobuf.Bytes(2, contentKeyIV),
      protobuf.Bytes(3, encryptedKey),
   }
   keyContainerBytes, _ := keyContainerMessage.Encode()
   licenseMessage := protobuf.Message{protobuf.Bytes(3, keyContainerBytes)}
   licenseBytes, _ := licenseMessage.Encode()
   signedResponse := protobuf.Message{
      protobuf.Varint(1, 2),
      protobuf.Bytes(2, licenseBytes),
      protobuf.Bytes(3, []byte{0x01, 0x02}),
      protobuf.Bytes(4, encryptedSessionKey),
   }
   signedBytes, _ := signedResponse.Encode()

   // == Step 4: Call our function to parse the response ==
   parsed, err := ParseLicenseResponse(signedBytes, dummyOriginalRequest, privateKey)
   if err != nil {
      t.Fatalf("ParseLicenseResponse failed: %v", err)
   }

   // == Step 5: Verify the result ==
   if parsed.Error != nil {
      t.Fatal("Expected Keys, but got an Error")
   }
   if parsed.Keys == nil {
      t.Fatal("Expected Keys, but got nil")
   }
   if len(parsed.Keys) != 1 {
      t.Fatalf("Expected 1 key, got %d", len(parsed.Keys))
   }
   if !bytes.Equal(parsed.Keys[0].Key, plaintextContentKey) {
      t.Errorf("Decrypted key mismatch!\nGot:  %x\nWant: %x", parsed.Keys[0].Key, plaintextContentKey)
   }
}

// TestParseLicenseResponse_Error tests parsing a valid error response.
func TestParseLicenseResponse_Error(t *testing.T) {
   privateKey := loadTestKey(t)
   expectedCode := uint64(1)
   dummyOriginalRequest := []byte{0xAA, 0xBB, 0xCC}

   errorMsg := protobuf.Message{protobuf.Varint(1, expectedCode)}
   errorBytes, _ := errorMsg.Encode()

   signedResponse := protobuf.Message{
      protobuf.Varint(1, 3),
      protobuf.Bytes(2, errorBytes),
      protobuf.Bytes(3, []byte{0x01, 0x02}),
   }
   signedBytes, _ := signedResponse.Encode()

   parsed, err := ParseLicenseResponse(signedBytes, dummyOriginalRequest, privateKey)
   if err != nil {
      t.Fatalf("ParseLicenseResponse failed: %v", err)
   }

   if parsed.Keys != nil {
      t.Fatal("Expected an Error, but got Keys")
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
   // Corrected argument order
   signedMsg, err := NewSignedRequest(reqBytes, privateKey)
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
