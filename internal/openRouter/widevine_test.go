package widevine

import (
   "41.neocities.org/protobuf"
   "bytes"
   "testing"
)

func check(t *testing.T, err error) {
   t.Helper()
   if err != nil {
      t.Fatalf("An unexpected error occurred: %v", err)
   }
}

// Test parsing the WidevineCencHeader protobuf data (for inspection purposes).
func TestParseWidevineHeader(t *testing.T) {
   keyID1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x01, 0x02, 0x03}
   contentID := []byte("test_content_id")

   headerMsg := protobuf.Message{
      protobuf.NewBytes(WidevineCencHeader_KeyId, keyID1),
      protobuf.NewBytes(WidevineCencHeader_ContentId, contentID),
   }
   headerBytes, err := headerMsg.Encode()
   check(t, err)

   header, err := ParseWidevineHeader(headerBytes)
   check(t, err)

   if !bytes.Equal(header.ContentID, contentID) {
      t.Errorf("Mismatched ContentID. Got %s, expected %s", header.ContentID, contentID)
   }
   if len(header.KeyIDs) != 1 {
      t.Fatalf("Expected 1 KeyID, got %d", len(header.KeyIDs))
   }
   if !bytes.Equal(header.KeyIDs[0], keyID1) {
      t.Errorf("Mismatched KeyID. Got %x, expected %x", header.KeyIDs[0], keyID1)
   }
}

// Test the full flow from header bytes -> request -> challenge.
func TestLicenseRequestAndChallenge(t *testing.T) {
   // 1. Create mock WidevineCencHeader protobuf data
   keyID := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd}
   contentID := []byte("my_content")
   headerMsg := protobuf.Message{
      protobuf.NewBytes(WidevineCencHeader_KeyId, keyID),
      protobuf.NewBytes(WidevineCencHeader_ContentId, contentID),
   }
   headerBytes, err := headerMsg.Encode()
   check(t, err)

   // 2. Create mock client info data
   clientInfoMsg := protobuf.Message{
      protobuf.NewString(ClientInfo_DeviceModel, "GoTest"),
   }
   clientInfoBytes, err := clientInfoMsg.Encode()
   check(t, err)

   // 3. Create the license request directly from the header bytes
   licenseRequest, err := NewLicenseRequest(headerBytes, clientInfoBytes)
   check(t, err)

   // 4. Build the final challenge
   challengeBytes, err := BuildChallenge(licenseRequest)
   check(t, err)

   // 5. Parse and verify the final challenge
   var signedMsg protobuf.Message
   err = signedMsg.Parse(challengeBytes)
   check(t, err)
   licenseRequestField, ok := signedMsg.Field(SignedMessage_Msg)
   if !ok {
      t.Fatal("Challenge is missing inner message payload")
   }

   var parsedRequest protobuf.Message
   err = parsedRequest.Parse(licenseRequestField.Bytes)
   check(t, err)

   parsedContentId, ok := parsedRequest.Field(LicenseRequest_ContentId)
   if !ok || !bytes.Equal(parsedContentId.Bytes, contentID) {
      t.Errorf("Parsed content ID does not match original")
   }
   parsedKeyId, ok := parsedRequest.Field(LicenseRequest_KeyId)
   if !ok || !bytes.Equal(parsedKeyId.Bytes, keyID) {
      t.Errorf("Parsed key ID does not match original")
   }
   parsedClientInfoField, ok := parsedRequest.Field(LicenseRequest_ClientInfo)
   if !ok || parsedClientInfoField.Message == nil {
      t.Fatal("Parsed request is missing client info or it's not a sub-message")
   }
   modelField, ok := parsedClientInfoField.Message.Field(ClientInfo_DeviceModel)
   if !ok || string(modelField.Bytes) != "GoTest" {
      t.Errorf("Parsed device model does not match. Got %s", string(modelField.Bytes))
   }
}

// Test parsing a license response. (Unchanged)
func TestParseLicenseResponse(t *testing.T) {
   keyID1 := []byte{0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44}
   keyValue1 := []byte{0xda, 0xd1, 0xb2, 0xd3, 0xda, 0xd1, 0xb2, 0xd3, 0xda, 0xd1, 0xb2, 0xd3, 0xda, 0xd1, 0xb2, 0xd3}

   keyMsg1 := protobuf.NewMessage(License_Key,
      protobuf.NewBytes(License_Key_Id, keyID1),
      protobuf.NewBytes(License_Key_Key, keyValue1),
      protobuf.NewVarint(License_Key_Type, 4), // CONTENT type
   )

   licenseProto := protobuf.Message{keyMsg1}
   licenseProtoBytes, err := licenseProto.Encode()
   check(t, err)

   signedMsg := protobuf.Message{
      protobuf.NewVarint(SignedMessage_Type, SignedMessageType_LICENSE),
      protobuf.NewBytes(SignedMessage_Msg, licenseProtoBytes),
   }
   mockLicenseResponseBytes, err := signedMsg.Encode()
   check(t, err)

   license, err := ParseLicenseResponse(mockLicenseResponseBytes)
   check(t, err)

   if license == nil {
      t.Fatal("ParseLicenseResponse returned nil license")
   }
   if len(license.Keys) != 1 {
      t.Fatalf("Expected 1 key, got %d", len(license.Keys))
   }

   if !bytes.Equal(license.Keys[0].ID, keyID1) {
      t.Errorf("Key 1 ID mismatch. Got %x, want %x", license.Keys[0].ID, keyID1)
   }
}
