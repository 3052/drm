package widevine

import (
   "bytes"
   "crypto"
   "crypto/rand"
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

// TestSignedMessageCreation checks that the session key (public key) is correctly generated.
func TestSignedMessageCreation(t *testing.T) {
   pkcs8, _ := base64.StdEncoding.DecodeString(testPrivateKeyB64)
   privateKey, _ := ParsePrivateKey(pkcs8)
   req := NewLicenseRequest([]byte{1}, []byte{2}, 1)
   reqBytes, _ := req.Encode()

   signedMsg, err := NewSignedRequest(privateKey, reqBytes)
   if err != nil {
      t.Fatalf("Failed to create signed request: %v", err)
   }

   // Verify that the session key was added
   if signedMsg.SessionKey == nil || len(signedMsg.SessionKey.Bytes) == 0 {
      t.Fatal("SessionKey was not automatically generated in the signed request")
   }

   // Verify the signature for good measure
   verifySignature(t, signedMsg.Msg.Bytes, signedMsg.Signature.Bytes)
}

// TestLicenseKeyDecryption tests the full flow of parsing a license and decrypting the key.
func TestLicenseKeyDecryption(t *testing.T) {
   // 1. Get our test key pair
   pkcs8, _ := base64.StdEncoding.DecodeString(testPrivateKeyB64)
   privateKey, _ := ParsePrivateKey(pkcs8)
   publicKey := &privateKey.PublicKey

   // 2. Define a plaintext content key
   plaintextContentKey := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

   // 3. Simulate the server: Encrypt the content key with the public key
   encryptedContentKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, plaintextContentKey, nil)
   if err != nil {
      t.Fatalf("Failed to simulate server key encryption: %v", err)
   }

   // 4. Manually construct a protobuf License message containing the encrypted key
   //    License -> key (field 3) -> KeyContainer message
   //    KeyContainer -> key (field 3) -> bytes (encrypted key)
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

// verifySignature is a helper function to verify a signature to avoid code duplication.
func verifySignature(t *testing.T, msg, signature []byte) {
   pubBytes, _ := base64.StdEncoding.DecodeString(testPublicKeyB64)
   pub, _ := x509.ParsePKIXPublicKey(pubBytes)
   publicKey := pub.(*rsa.PublicKey)
   msgHash := sha1.New()
   msgHash.Write(msg)
   hashed := msgHash.Sum(nil)
   err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, hashed, signature)
   if err != nil {
      t.Errorf("Signature verification failed: %v", err)
   }
}
