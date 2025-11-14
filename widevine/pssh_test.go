package widevine

import (
   "bytes"
   "testing"
)

// TestBuildPsshData_OnlyKeyIDs verifies encoding with only key IDs.
func TestBuildPsshData_OnlyKeyIDs(t *testing.T) {
   keyIDs := [][]byte{
      {0x01, 0x02, 0x03, 0x04},
      {0x05, 0x06, 0x07, 0x08},
   }
   encoded, err := BuildPsshData(keyIDs, nil)
   if err != nil {
      t.Fatalf("BuildPsshData failed: %v", err)
   }
   // Expected wire format:
   // Field 2 (key_ids, bytes): tag 0x12, length 4, value 01020304
   // Field 2 (key_ids, bytes): tag 0x12, length 4, value 05060708
   expected := []byte{
      0x12, 0x04, 0x01, 0x02, 0x03, 0x04,
      0x12, 0x04, 0x05, 0x06, 0x07, 0x08,
   }
   if !bytes.Equal(encoded, expected) {
      t.Errorf("Encoded data mismatch.\nGot:  %x\nWant: %x", encoded, expected)
   }
}

// TestBuildPsshData_OnlyContentID verifies encoding with only a content ID.
func TestBuildPsshData_OnlyContentID(t *testing.T) {
   contentID := []byte{0xDE, 0xAD, 0xBE, 0xEF}
   encoded, err := BuildPsshData(nil, contentID)
   if err != nil {
      t.Fatalf("BuildPsshData failed: %v", err)
   }
   // Expected wire format:
   // Field 4 (content_id, bytes): tag 0x22, length 4, value DEADBEAF
   expected := []byte{
      0x22, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
   }
   if !bytes.Equal(encoded, expected) {
      t.Errorf("Encoded data mismatch.\nGot:  %x\nWant: %x", encoded, expected)
   }
}

// TestBuildPsshData_Both verifies encoding with both key IDs and a content ID.
func TestBuildPsshData_Both(t *testing.T) {
   keyIDs := [][]byte{
      {0xAA, 0xBB, 0xCC},
   }
   contentID := []byte("content_name")
   encoded, err := BuildPsshData(keyIDs, contentID)
   if err != nil {
      t.Fatalf("BuildPsshData failed: %v", err)
   }
   // Expected wire format (deterministic: key_ids then content_id):
   // Field 2 (key_ids, bytes): tag 0x12, length 3, value AABBCC
   // Field 4 (content_id, bytes): tag 0x22, length 12, value "content_name"
   expected := []byte{
      0x12, 0x03, 0xAA, 0xBB, 0xCC,
      0x22, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
   }
   if !bytes.Equal(encoded, expected) {
      t.Errorf("Encoded data mismatch.\nGot:  %x\nWant: %x", encoded, expected)
   }
}

// TestBuildPsshData_Empty verifies that nil inputs encode to an empty byte slice.
func TestBuildPsshData_Empty(t *testing.T) {
   encoded, err := BuildPsshData(nil, nil)
   if err != nil {
      t.Fatalf("BuildPsshData failed: %v", err)
   }
   if len(encoded) != 0 {
      t.Errorf("Expected empty byte slice for empty PSSH data, got %d bytes", len(encoded))
   }
}
