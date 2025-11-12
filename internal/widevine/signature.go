package widevine

import (
   "crypto"
   "crypto/rand"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
   "fmt"
)

// ParsePrivateKey parses a PEM-encoded private key from a byte slice.
// It supports both PKCS#8 ("PRIVATE KEY") and PKCS#1 ("RSA PRIVATE KEY") formats.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
   block, _ := pem.Decode(pemBytes)
   if block == nil {
      return nil, fmt.Errorf("failed to decode PEM block containing private key")
   }

   // First, try to parse as a PKCS#8-encoded key
   key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
   if err == nil {
      rsaKey, ok := key.(*rsa.PrivateKey)
      if !ok {
         return nil, fmt.Errorf("key in PEM block is not an RSA private key")
      }
      return rsaKey, nil
   }

   // If PKCS#8 parsing fails, try to parse as a PKCS#1-encoded key
   rsaKey, errPKCS1 := x509.ParsePKCS1PrivateKey(block.Bytes)
   if errPKCS1 != nil {
      // Return a more informative error if both parsing methods fail
      return nil, fmt.Errorf("failed to parse private key; tried PKCS#8 (%v) and PKCS#1 (%v)", err, errPKCS1)
   }

   return rsaKey, nil
}

// signMessage computes the SHA-1 hash of the message and signs it using the
// private key with RSA-PKCS#1 v1.5 padding.
func signMessage(privateKey *rsa.PrivateKey, message []byte) ([]byte, error) {
   hash := sha1.New()
   hash.Write(message)
   hashed := hash.Sum(nil)

   signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashed)
   if err != nil {
      return nil, fmt.Errorf("failed to sign message: %w", err)
   }
   return signature, nil
}

// decryptKey decrypts a ciphertext using RSA-OAEP with SHA-1.
// This is used to decrypt the content key from the license server.
func decryptKey(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
   // The label for Widevine's OAEP is typically nil or empty.
   // The hash function is SHA-1.
   plaintext, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, ciphertext, nil)
   if err != nil {
      return nil, fmt.Errorf("failed to decrypt key with RSA-OAEP: %w", err)
   }
   return plaintext, nil
}
