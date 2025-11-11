package widevine

import (
   "41.neocities.org/protobuf"
   "bytes"
   "encoding/binary"
   "testing"
)

// Helper function to check for errors and fail the test if one occurs.
func check(t *testing.T, err error) {
   t.Helper()
   if err != nil {
      t.Fatalf("An unexpected error occurred: %v", err)
   }
}

// Test parsing of Widevine PSSH boxes.
func TestParsePSSH(t *testing.T) {
   t.Run("Version 1 PSSH Box", func(t *testing.T) {
      // --- Setup: Build a mock V1 PSSH box ---
      // PSSH Data (WidevineCencHeader)
      cencHeader := protobuf.Message{
         protobuf.NewString(WidevineCencHeader_Provider, "widevine_test"),
         protobuf.NewBytes(WidevineCencHeader_ContentId, []byte("test_content")),
      }
      cencHeaderBytes, err := cencHeader.Encode()
      check(t, err)

      // Key ID
      keyID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

      var buf bytes.Buffer
      // Box Header
      // Size will be calculated at the end
      buf.Write(make([]byte, 4)) // Placeholder for size
      buf.WriteString("pssh")
      // Full Box Header
      buf.WriteByte(1)           // Version 1
      buf.Write([]byte{0, 0, 0}) // Flags
      // PSSH Body
      buf.Write(SystemID)                                                // System ID
      binary.Write(&buf, binary.BigEndian, uint32(1))                    // Key ID Count
      buf.Write(keyID)                                                   // Key ID
      binary.Write(&buf, binary.BigEndian, uint32(len(cencHeaderBytes))) // Data size
      buf.Write(cencHeaderBytes)                                         // Data

      // Finalize size
      boxBytes := buf.Bytes()
      binary.BigEndian.PutUint32(boxBytes, uint32(len(boxBytes)))

      // --- Test ---
      psshData, err := ParsePSSH(boxBytes)
      check(t, err)

      // --- Assertions ---
      if len(psshData.KeyIDs) != 1 {
         t.Fatalf("Expected 1 KeyID, got %d", len(psshData.KeyIDs))
      }
      if !bytes.Equal(psshData.KeyIDs[0], keyID) {
         t.Errorf("Mismatched KeyID. Got %x, expected %x", psshData.KeyIDs[0], keyID)
      }
      providerField, ok := psshData.Data.Field(WidevineCencHeader_Provider)
      if !ok || string(providerField.Bytes) != "widevine_test" {
         t.Errorf("Failed to correctly parse provider from CencHeader")
      }
   })

   t.Run("Version 0 PSSH Box", func(t *testing.T) {
      // --- Setup: Build a mock V0 PSSH box ---
      keyID := []byte{0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
      cencHeader := protobuf.Message{
         protobuf.NewString(WidevineCencHeader_Provider, "widevine_test_v0"),
         // In v0, Key ID is in the data payload
         protobuf.NewBytes(WidevineCencHeader_KeyId, keyID),
      }
      cencHeaderBytes, err := cencHeader.Encode()
      check(t, err)

      var buf bytes.Buffer
      // Box Header
      buf.Write(make([]byte, 4)) // Placeholder for size
      buf.WriteString("pssh")
      // Full Box Header
      buf.WriteByte(0)           // Version 0
      buf.Write([]byte{0, 0, 0}) // Flags
      // PSSH Body
      buf.Write(SystemID)                                                // System ID
      binary.Write(&buf, binary.BigEndian, uint32(len(cencHeaderBytes))) // Data size
      buf.Write(cencHeaderBytes)                                         // Data

      boxBytes := buf.Bytes()
      binary.BigEndian.PutUint32(boxBytes, uint32(len(boxBytes)))

      // --- Test ---
      psshData, err := ParsePSSH(boxBytes)
      check(t, err)

      // --- Assertions ---
      if len(psshData.KeyIDs) != 1 {
         t.Fatalf("Expected 1 KeyID, got %d", len(psshData.KeyIDs))
      }
      if !bytes.Equal(psshData.KeyIDs[0], keyID) {
         t.Errorf("Mismatched KeyID. Got %x, expected %x", psshData.KeyIDs[0], keyID)
      }
      providerField, ok := psshData.Data.Field(WidevineCencHeader_Provider)
      if !ok || string(providerField.Bytes) != "widevine_test_v0" {
         t.Errorf("Failed to correctly parse provider from CencHeader")
      }
   })
}

// Test creating a license request and building a challenge.
func TestLicenseRequestAndChallenge(t *testing.T) {
   // --- Setup ---
   client := Client{
      WidevineCDMVersion: "16.0.0",
      OS:                 "TestOS",
      Arch:               "x86_64",
      DeviceModel:        "GoTest",
   }
   clientInfo := client.Build()

   keyID1 := []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
   keyIDs := [][]byte{keyID1}

   // --- Test ---
   licenseRequest, err := NewLicenseRequest(nil, clientInfo, keyIDs)
   check(t, err)

   challengeBytes, err := BuildChallenge(licenseRequest)
   check(t, err)

   // --- Assertions: Parse the generated challenge to verify its contents ---
   var signedMsg protobuf.Message
   err = signedMsg.Parse(challengeBytes)
   check(t, err)

   msgType, ok := signedMsg.Field(SignedMessage_Type)
   if !ok || msgType.Numeric != SignedMessageType_LICENSE_REQUEST {
      t.Fatalf("Challenge has wrong message type. Got %v, want %d", msgType, SignedMessageType_LICENSE_REQUEST)
   }

   licenseRequestBytes, ok := signedMsg.Field(SignedMessage_Msg)
   if !ok {
      t.Fatal("Challenge is missing inner message payload")
   }

   var parsedRequest protobuf.Message
   err = parsedRequest.Parse(licenseRequestBytes.Bytes)
   check(t, err)

   // Check key ID
   parsedKeyId, ok := parsedRequest.Field(LicenseRequest_KeyId)
   if !ok || !bytes.Equal(parsedKeyId.Bytes, keyID1) {
      t.Errorf("Parsed key ID does not match original")
   }

   // Check client info
   parsedClientInfoField, ok := parsedRequest.Field(LicenseRequest_ClientInfo)
   if !ok {
      t.Fatal("Parsed request is missing client info")
   }
   modelField, ok := parsedClientInfoField.Message.Field(ClientInfo_DeviceModel)
   if !ok || string(modelField.Bytes) != "GoTest" {
      t.Errorf("Parsed device model does not match. Got %s", string(modelField.Bytes))
   }
}

// Test parsing a license response.
func TestParseLicenseResponse(t *testing.T) {
   // --- Setup: Build a mock license response ---
   keyID1 := []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
   keyValue1 := []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
   keyID2 := []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
   keyValue2 := []byte{0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce}

   // Create License_Key messages
   keyMsg1 := protobuf.NewMessage(License_Key,
      protobuf.NewBytes(License_Key_Id, keyID1),
      protobuf.NewBytes(License_Key_Key, keyValue1),
      protobuf.NewVarint(License_Key_Type, KeyType_CONTENT),
   )
   keyMsg2 := protobuf.NewMessage(License_Key,
      protobuf.NewBytes(License_Key_Id, keyID2),
      protobuf.NewBytes(License_Key_Key, keyValue2),
      protobuf.NewVarint(License_Key_Type, KeyType_SIGNING),
   )

   // Create inner License message
   licenseProto := protobuf.Message{keyMsg1, keyMsg2}
   licenseProtoBytes, err := licenseProto.Encode()
   check(t, err)

   // Create outer SignedMessage
   signedMsg := protobuf.Message{
      protobuf.NewVarint(SignedMessage_Type, SignedMessageType_LICENSE),
      protobuf.NewBytes(SignedMessage_Msg, licenseProtoBytes),
   }
   mockLicenseResponseBytes, err := signedMsg.Encode()
   check(t, err)

   // --- Test ---
   license, err := ParseLicenseResponse(mockLicenseResponseBytes)
   check(t, err)

   // --- Assertions ---
   if license == nil {
      t.Fatal("ParseLicenseResponse returned nil license")
   }
   if len(license.Keys) != 2 {
      t.Fatalf("Expected 2 keys, got %d", len(license.Keys))
   }

   // Check Key 1
   if !bytes.Equal(license.Keys[0].ID, keyID1) {
      t.Errorf("Key 1 ID mismatch. Got %x, want %x", license.Keys[0].ID, keyID1)
   }
   if !bytes.Equal(license.Keys[0].Value, keyValue1) {
      t.Errorf("Key 1 Value mismatch. Got %x, want %x", license.Keys[0].Value, keyValue1)
   }
   if license.Keys[0].Type != "CONTENT" {
      t.Errorf("Key 1 Type mismatch. Got %s, want CONTENT", license.Keys[0].Type)
   }

   // Check Key 2
   if !bytes.Equal(license.Keys[1].ID, keyID2) {
      t.Errorf("Key 2 ID mismatch. Got %x, want %x", license.Keys[1].ID, keyID2)
   }
   if !bytes.Equal(license.Keys[1].Value, keyValue2) {
      t.Errorf("Key 2 Value mismatch. Got %x, want %x", license.Keys[1].Value, keyValue2)
   }
   if license.Keys[1].Type != "SIGNING" {
      t.Errorf("Key 2 Type mismatch. Got %s, want SIGNING", license.Keys[1].Type)
   }

}
