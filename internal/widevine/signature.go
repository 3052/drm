package widevine

import (
   "crypto"
   "crypto/rand"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "fmt"
)

// ParsePrivateKey parses a PKCS#8 encoded private key from a byte slice.
func ParsePrivateKey(pkcs8 []byte) (*rsa.PrivateKey, error) {
   key, err := x509.ParsePKCS8PrivateKey(pkcs8)
   if err != nil {
      // As a fallback for older PKCS#1 keys if PKCS#8 fails.
      if key, err := x509.ParsePKCS1PrivateKey(pkcs8); err == nil {
         return key, nil
      }
      return nil, fmt.Errorf("failed to parse private key as PKCS#8 or PKCS#1: %w", err)
   }
   rsaKey, ok := key.(*rsa.PrivateKey)
   if !ok {
      return nil, fmt.Errorf("key is not an RSA private key")
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
