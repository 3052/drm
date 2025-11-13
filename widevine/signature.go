package widevine

import (
   "crypto"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
   "errors"
   "fmt"
)

// noopReader is a deterministic implementation of io.Reader that performs
// no operations on the provided buffer. It leaves the buffer as-is (which
// is typically zero-initialized by the caller) and returns its length.
type noopReader struct{}

// Read does not modify the input slice and returns its length, satisfying
// the io.Reader interface for deterministic PSS signing.
func (noopReader) Read(p []byte) (n int, err error) {
   return len(p), nil
}

// ParsePrivateKey parses a PEM-encoded private key from a byte slice.
// It supports both PKCS#8 ("PRIVATE KEY") and PKCS#1 ("RSA PRIVATE KEY") formats.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
   block, _ := pem.Decode(pemBytes)
   if block == nil {
      return nil, errors.New("failed to decode PEM block containing private key")
   }

   // First, try to parse as a PKCS#8-encoded key
   key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
   if err == nil {
      rsaKey, ok := key.(*rsa.PrivateKey)
      if !ok {
         return nil, errors.New("key in PEM block is not an RSA private key")
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
// RSASSA-PSS scheme.
func signMessage(privateKey *rsa.PrivateKey, message []byte) ([]byte, error) {
   // 1. Hash the message using SHA-1.
   hash := sha1.New()
   hash.Write(message)
   hashed := hash.Sum(nil)

   // 2. Set PSS options.
   opts := &rsa.PSSOptions{
      SaltLength: rsa.PSSSaltLengthEqualsHash,
      Hash:       crypto.SHA1,
   }

   // 3. Sign the hash using the RSASSA-PSS scheme with a deterministic no-op reader.
   signature, err := rsa.SignPSS(noopReader{}, privateKey, crypto.SHA1, hashed, opts)
   if err != nil {
      return nil, fmt.Errorf("failed to sign message with PSS: %w", err)
   }
   return signature, nil
}
