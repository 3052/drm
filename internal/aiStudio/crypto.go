package widevine

import (
   "crypto"
   "crypto/rand"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
   "fmt"
   "os"
)

// LoadPrivateKey loads a PEM-encoded PKCS#1 RSA private key from the specified file.
func LoadPrivateKey(filePath string) (*rsa.PrivateKey, error) {
   keyData, err := os.ReadFile(filePath)
   if err != nil {
      return nil, fmt.Errorf("failed to read private key file: %w", err)
   }

   block, _ := pem.Decode(keyData)
   if block == nil {
      return nil, fmt.Errorf("failed to decode PEM block from private key file")
   }

   if block.Type != "RSA PRIVATE KEY" {
      return nil, fmt.Errorf("invalid PEM block type: expected 'RSA PRIVATE KEY', got '%s'", block.Type)
   }

   privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
   }

   return privateKey, nil
}

// SignRequestData signs the given data using the provided RSA private key.
// It uses RSASSA-PSS with a SHA-1 hash, as specified by the signing algorithm.
func SignRequestData(privateKey *rsa.PrivateKey, requestData []byte) ([]byte, error) {
   // First, compute the SHA-1 hash of the message.
   digest := sha1.Sum(requestData)

   // Set PSS options. The salt length should match the hash function's output size.
   pssOptions := &rsa.PSSOptions{
      SaltLength: sha1.Size,
      Hash:       crypto.SHA1,
   }

   // Sign the hashed message.
   signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA1, digest[:], pssOptions)
   if err != nil {
      return nil, fmt.Errorf("failed to sign data with PSS: %w", err)
   }

   return signature, nil
}
