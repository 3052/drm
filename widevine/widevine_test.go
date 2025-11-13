package widevine

import (
   "bytes"
   "crypto"
   "crypto/rsa"
   "crypto/sha1"
   "testing"
)

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
