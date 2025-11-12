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
      return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
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
