package widevine

import (
   "bytes"
   "testing"
)

// TestEncodeLicenseRequest verifies that a new LicenseRequest is encoded correctly.
func TestEncodeLicenseRequest(t *testing.T) {
   contentID := []byte{0xDE, 0xAD, 0xBE, 0xEF}
   requestType := 1 // NEW

   req := NewLicenseRequest(contentID, requestType)
   encoded, err := req.Encode()
   if err != nil {
      t.Fatalf("Failed to encode LicenseRequest: %v", err)
   }

   // Manually construct the expected protobuf bytes for verification.
   // Field 2 (content_id, Message) -> Tag 0x12
   //   Length of ContentIdentification message: 8
   //   Field 1 (widevine_pssh_data, Message) -> Tag 0x0a
   //     Length of WidevinePsshData message: 6
   //     Field 1 (pssh_data, Bytes) -> Tag 0x0a
   //       Length of pssh_data: 4
   //       Value: DE AD BE EF
   // Field 3 (type, Varint) -> Tag 0x18
   //   Value: 1
   expected := []byte{
      0x12, 0x08, 0x0a, 0x06, 0x0a, 0x04, 0xde, 0xad, 0xbe, 0xef,
      0x18, 0x01,
   }

   if !bytes.Equal(encoded, expected) {
      t.Errorf("Encoded LicenseRequest does not match expected bytes.\nGot:  %x\nWant: %x", encoded, expected)
   }
}

// TestEncodeSignedMessage verifies that a SignedMessage is encoded correctly.
func TestEncodeSignedMessage(t *testing.T) {
   msgBytes := []byte{0x01, 0x02, 0x03}
   sigBytes := []byte{0x04, 0x05, 0x06}
   msgType := 1 // LICENSE_REQUEST

   sm := NewSignedMessage(msgType, msgBytes, sigBytes)
   encoded, err := sm.Encode()
   if err != nil {
      t.Fatalf("Failed to encode SignedMessage: %v", err)
   }

   // Manually construct expected bytes.
   // Field 1 (Type, Varint) -> Tag 0x08, Value 1
   // Field 2 (Msg, Bytes) -> Tag 0x12, Length 3, Value 01 02 03
   // Field 3 (Signature, Bytes) -> Tag 0x1a, Length 3, Value 04 05 06
   expected := []byte{
      0x08, 0x01,
      0x12, 0x03, 0x01, 0x02, 0x03,
      0x1a, 0x03, 0x04, 0x05, 0x06,
   }

   if !bytes.Equal(encoded, expected) {
      t.Errorf("Encoded SignedMessage does not match expected bytes.\nGot:  %x\nWant: %x", encoded, expected)
   }
}

// TestParseLicense verifies that a License message is parsed correctly.
func TestParseLicense(t *testing.T) {
   // Construct a sample License protobuf message.
   // Field 2 (policy, Message) -> Tag 0x12
   //   Length 2
   //   Field 1 (can_play, Varint) -> Tag 0x08, Value 1 (true)
   // Field 3 (key, Message, repeated) -> Tag 0x1a
   //   Length 5
   //   Field 1 (id, Bytes) -> Tag 0x0a, Length 3, Value 01 02 03
   licenseBytes := []byte{
      0x12, 0x02, 0x08, 0x01,
      0x1a, 0x05, 0x0a, 0x03, 0x01, 0x02, 0x03,
   }

   license, err := ParseLicense(licenseBytes)
   if err != nil {
      t.Fatalf("Failed to parse License: %v", err)
   }

   if license.Policy == nil {
      t.Fatal("Parsed license policy is nil")
   }
   if license.Policy.Tag.FieldNum != 2 {
      t.Errorf("Expected policy field number 2, got %d", license.Policy.Tag.FieldNum)
   }

   if len(license.Key) != 1 {
      t.Fatalf("Expected 1 key, got %d", len(license.Key))
   }
   key := license.Key[0]
   if key.Tag.FieldNum != 3 {
      t.Errorf("Expected key field number 3, got %d", key.Tag.FieldNum)
   }
}

// TestParseLicenseError verifies that a LicenseError message is parsed correctly.
func TestParseLicenseError(t *testing.T) {
   // Field 1 (error_code, Varint) -> Tag 0x08, Value 1
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

// TestSignedMessageRoundtrip tests encoding and then decoding a SignedMessage.
func TestSignedMessageRoundtrip(t *testing.T) {
   // 1. Create and encode a LicenseRequest
   req := NewLicenseRequest([]byte{0xAA, 0xBB, 0xCC}, 1)
   reqBytes, err := req.Encode()
   if err != nil {
      t.Fatalf("Failed to encode request for roundtrip test: %v", err)
   }

   // 2. Wrap it in a SignedMessage
   original := NewSignedMessage(1, reqBytes, []byte{0xDD, 0xEE, 0xFF})

   // 3. Encode the SignedMessage
   encoded, err := original.Encode()
   if err != nil {
      t.Fatalf("Failed to encode SignedMessage for roundtrip test: %v", err)
   }

   // 4. Parse the SignedMessage
   parsed, err := ParseSignedMessage(encoded)
   if err != nil {
      t.Fatalf("Failed to parse SignedMessage for roundtrip test: %v", err)
   }

   // 5. Verify the fields match
   if original.Type.Numeric != parsed.Type.Numeric {
      t.Errorf("Type mismatch: got %d, want %d", parsed.Type.Numeric, original.Type.Numeric)
   }
   if !bytes.Equal(original.Msg.Bytes, parsed.Msg.Bytes) {
      t.Errorf("Msg mismatch: got %x, want %x", parsed.Msg.Bytes, original.Msg.Bytes)
   }
   if !bytes.Equal(original.Signature.Bytes, parsed.Signature.Bytes) {
      t.Errorf("Signature mismatch: got %x, want %x", parsed.Signature.Bytes, original.Signature.Bytes)
   }
}
