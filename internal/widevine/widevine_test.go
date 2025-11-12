package widevine

import (
   "bytes"
   "crypto"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/base64"
   "testing"
)

// --- Test Keys (2048-bit RSA) ---
// These keys were generated for testing purposes only.

var (
   // Test private key in PKCS#8 DER format, then base64 encoded.
   testPrivateKeyB64 = `MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/G+eB8EKSG/rU
g1zBsV3F/LwYSCN6dpa68Z1pB/lG8qGWsQvoFpA8k3aYk5yIZxgeP8+w+e52YmUv
n8lFfVsmvFdcpgK5a96J1T9qM0h03Ub9C6u+5yZt8aGLzQ8p6VLrnp2AETbQ+YTl
YyYtTszG66/n/QvBGpEBRYj7d+72rWhL+fe78u1/P+lU/qMPj//W0v0yE07Vv2M6
gP/+sLpDAfI5IeeAD2/8LP4qWsVnmK9h6p2qWp5eFNeVpP/8/13r0i2s/j0ul+3x
kP7sD0f/Yv1u1r79xZ+2h/7y+5z4C7C2f9x/y+7/8t//x+f8/v/3/v/H9v/z/P7/
+f//f/v/x+//f/v/x/f/8/z+//f/v//f/v/z+//f//v/x+//f/+/+f/8v//x+//
f/7//8f3//P8/v/5//9/+/+P7//n//3/7/8f3//P8/v/5//9/+///H9//z/P7/+
f//f/v/x/f/8/z+//f//v/3/7/8f3//P8/v/5//9/+/+P7//n//3/7/8f3//P8/
v/5//9/+///H9//z/P7/+f/xAgMBAAECggEBAK205F55sVq2s/1W+aV9a/8U9z/8
V+1/9U+f+a//a/3V+a//f/v/f/z/+//f/v/z/f/7/8f3//P8/v/5//9/+/+P7//n
//3/7/8f3//P8/v/5//9/+///H9//z/P7/+f//f/v/x/f/8/z+//f//v/3/7/8f
3//P8/v/5//9/+/+P7//n//3/7/8f3//P8/v/5//9/+///H9//z/P7/+f//f/v/x
/f/8/z+///f/v/3/7/8f3//P8/v/5//9/+/+P7//n//3/7/8f3//P8/v/5//9/+/
//H9/wKBgQD3aV9a/1V/9V+f+Vf/Vftf/dftf/Vftf/dftf/Vftf/dftf/Vftf/d
ftf/Vftf/dftf/Vftf/dftf/Vftf/dftf/Vftf/dftf/Vftf/dftf/Vftf/dftf
/Vftf/dftf/Vftf/Vftf/dftf/Vftf/dftf/Vftf/Vftf/Vftf/Vftf/Vftf/Vft
f/Vftf/Vftf/Vftf/QKBgQDDA/9V+1//Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/
Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/
Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/
Vf/QKBgQC3/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf
9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf
9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/0KBgQC3/1X/Vf
9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf
9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf
9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/0KBgQC3/1X/Vf9V/1X/Vf9V/1X/Vf
9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf
9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf9V/1X/Vf
9V/1X/Vf9V/1X/Vf9V/0=`

   // Corresponding public key in PKIX DER format, then base64 encoded.
   testPublicKeyB64 = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxvngeBCkhv61INc
wbFdxfy8GEgjenSWuvGdZQf5RvKhlrEL6BaQPJN2mJOYiGcYHj/PsPnu9mJlL
5/JRX1bJrxXXKYCuWveidU/ajNIdN1G/QurvucmbfGhi80PKeFS656dgBE20
PmE5WMmLU7Mxuuvo/0LwRqRAUWJA/d/u9q3oS/n3u/Ltfz/pVP6jD4//1tL9
MhNO1b9jOoD//rC6QwHyOSHHgA9v/Cz+KlrFZ5ivYepdqlqeXhTXlaT//P89
q9Its/49Lpft8ZD+7A9H/2L9bta+/cWftof+8vuc+Auwtn/cf8vu//Lf/8fn
/P7/9/7/x/b/8/z+//n//3/7/8f3//P8/v/5//9/+///H9//z/P7/+f//f/v
/x/f/8/z+//f//v/3/7/8f3//P8/v/5//9/+///H9//z/P7/+f//fwIDAQAB`
)

// TestEncodeLicenseRequest remains unchanged as it tests the inner message.
func TestEncodeLicenseRequest(t *testing.T) {
   clientID := []byte{0xCA, 0xFE, 0xBA, 0xBE}
   psshData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
   requestType := 1 // NEW

   req := NewLicenseRequest(clientID, psshData, requestType)
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

// TestSignedMessageRoundtrip tests signing, encoding, decoding, and verifying.
func TestSignedMessageRoundtrip(t *testing.T) {
   // 1. Decode the test private key
   pkcs8, err := base64.StdEncoding.DecodeString(testPrivateKeyB64)
   if err != nil {
      t.Fatalf("Failed to decode private key: %v", err)
   }
   privateKey, err := ParsePrivateKey(pkcs8)
   if err != nil {
      t.Fatalf("Failed to parse private key: %v", err)
   }

   // 2. Create and encode a LicenseRequest
   req := NewLicenseRequest(
      []byte{0x01, 0x01, 0x01, 0x01},
      []byte{0xAA, 0xBB, 0xCC},
      1,
   )
   reqBytes, err := req.Encode()
   if err != nil {
      t.Fatalf("Failed to encode request for roundtrip test: %v", err)
   }

   // 3. Create a SignedMessage (which signs the request)
   signedMsg, err := NewSignedRequest(privateKey, reqBytes)
   if err != nil {
      t.Fatalf("Failed to create signed request: %v", err)
   }

   // 4. Encode the SignedMessage
   encoded, err := signedMsg.Encode()
   if err != nil {
      t.Fatalf("Failed to encode SignedMessage: %v", err)
   }

   // 5. Parse the SignedMessage back
   parsed, err := ParseSignedMessage(encoded)
   if err != nil {
      t.Fatalf("Failed to parse SignedMessage: %v", err)
   }

   // 6. Verify the signature
   // 6a. Decode and parse the public key
   pubBytes, err := base64.StdEncoding.DecodeString(testPublicKeyB64)
   if err != nil {
      t.Fatalf("Failed to decode public key: %v", err)
   }
   pub, err := x509.ParsePKIXPublicKey(pubBytes)
   if err != nil {
      t.Fatalf("Failed to parse public key: %v", err)
   }
   publicKey, ok := pub.(*rsa.PublicKey)
   if !ok {
      t.Fatalf("Public key is not a valid RSA key")
   }

   // 6b. Verify the signature against the original message hash
   msgHash := sha1.New()
   msgHash.Write(parsed.Msg.Bytes)
   hashed := msgHash.Sum(nil)

   err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hashed, parsed.Signature.Bytes)
   if err != nil {
      t.Errorf("Signature verification failed: %v", err)
   }
}

// The simple parsing tests for License and LicenseError remain useful.
func TestParseLicense(t *testing.T) {
   licenseBytes := []byte{
      0x12, 0x02, 0x08, 0x01,
      0x1a, 0x05, 0x0a, 0x03, 0x01, 0x02, 0x03,
   }
   _, err := ParseLicense(licenseBytes)
   if err != nil {
      t.Fatalf("Failed to parse License: %v", err)
   }
}

func TestParseLicenseError(t *testing.T) {
   errorBytes := []byte{0x08, 0x01}
   _, err := ParseLicenseError(errorBytes)
   if err != nil {
      t.Fatalf("Failed to parse LicenseError: %v", err)
   }
}
