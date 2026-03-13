package playReady

import (
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "github.com/emmansun/gmsm/padding"
   "slices"
)

func (c *Chain) cipherData(key *xmlKey) ([]byte, error) {
   value := Data{
      CertificateChains: CertificateChains{
         CertificateChain: c.Encode(),
      },
      Features: Features{
         Feature: Feature{"AESCBC"}, // SCALABLE
      },
   }
   data, err := value.Marshal()
   if err != nil {
      return nil, err
   }
   block, err := aes.NewCipher(key.aesKey())
   if err != nil {
      return nil, err
   }
   data = padding.NewPKCS7Padding(aes.BlockSize).Pad(data)
   cipher.NewCBCEncrypter(block, key.aesIv()).CryptBlocks(data, data)
   return append(key.aesIv(), data...), nil
}

// Chain represents a chain of certificates.
type Chain struct {
   magic     [4]byte
   version   uint32
   length    uint32
   flags     uint32
   certCount uint32
   certs     []certificate
}

// DecodeChain decodes a byte slice into a new Chain structure.
func DecodeChain(data []byte) (*Chain, error) {
   chain := &Chain{}
   copied := copy(chain.magic[:], data)
   if string(chain.magic[:]) != "CHAI" {
      return nil, errors.New("failed to find chain magic")
   }
   data = data[copied:]
   chain.version = binary.BigEndian.Uint32(data)
   data = data[4:]
   chain.length = binary.BigEndian.Uint32(data)
   data = data[4:]
   chain.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   chain.certCount = binary.BigEndian.Uint32(data)
   data = data[4:]
   chain.certs = make([]certificate, chain.certCount)
   for i := range chain.certCount {
      var cert certificate
      bytesRead, err := cert.decode(data)
      if err != nil {
         return nil, err
      }
      chain.certs[i] = cert
      data = data[bytesRead:]
   }
   return chain, nil
}

// Encode encodes the Chain into a byte slice.
func (c *Chain) Encode() []byte {
   data := c.magic[:]
   data = binary.BigEndian.AppendUint32(data, c.version)
   data = binary.BigEndian.AppendUint32(data, c.length)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.certCount)
   for _, cert := range c.certs {
      data = append(data, cert.encode()...)
   }
   return data
}

// verify verifies the entire certificate chain.
func (c *Chain) verify() bool {
   // Start verification with the issuer key of the last certificate in the chain.
   modelBase := c.certs[len(c.certs)-1].signatureData.IssuerKey
   for i := len(c.certs) - 1; i >= 0; i-- {
      // Verify each certificate using the public key of its issuer.
      valid := c.certs[i].verify(modelBase[:])
      if !valid {
         return false
      }
      // The public key of the current certificate becomes the issuer key for
      // the next in the chain.
      modelBase = c.certs[i].keyInfo.keys[0].publicKey[:]
   }
   return true
}

// CreateLeaf creates a new leaf certificate and adds it to the chain.
func (c *Chain) CreateLeaf(modelKey, signingKey, encryptKey *ecdsa.PrivateKey) error {
   modelPub, err := PublicKeyBytes(modelKey)
   if err != nil {
      return err
   }
   // Verify that the provided modelKey matches the public key in the chain's
   // first certificate.
   if !bytes.Equal(c.certs[0].keyInfo.keys[0].publicKey[:], modelPub) {
      return errors.New("zgpriv not for cert")
   }
   // Verify the existing chain's validity.
   if !c.verify() {
      return errors.New("cert is not valid")
   }

   signPub, err := PublicKeyBytes(signingKey)
   if err != nil {
      return err
   }
   encPub, err := PublicKeyBytes(encryptKey)
   if err != nil {
      return err
   }

   // Assemble raw data for the unsigned certificate.
   var leafData bytes.Buffer
   {
      // Calculate digest for the signing key.
      digest := sha256.Sum256(signPub)
      // Initialize certificate information.
      var info certificateInfo
      info.New(c.certs[0].certificateInfo.securityLevel, digest[:])
      // Create FTLV (Fixed Tag Length Value) for certificate info.
      var value ftlv
      value.New(1, 1, info.encode())
      leafData.Write(value.encode())
   }
   {
      // Create a new device and its FTLV.
      var device1 device
      device1.New()
      var value ftlv
      value.New(1, 4, device1.encode())
      leafData.Write(value.encode())
   }
   {
      // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
      feature := features{
         entries:  1,
         features: []uint32{0xD},
      }
      // Create FTLV for features.
      var value ftlv
      value.New(1, 5, feature.encode())
      leafData.Write(value.encode())
   }
   {
      // Initialize key information for signing and encryption keys.
      var key keyInfo
      key.New(signPub, encPub)
      // Create FTLV for key information.
      var value ftlv
      value.New(1, 6, key.encode())
      leafData.Write(value.encode())
   }
   {
      // Create FTLV for manufacturer information, copying from the existing
      // chain's first cert.
      var value ftlv
      value.New(0, 7, c.certs[0].manufacturerInfo.encode())
      leafData.Write(value.encode())
   }
   // Create an unsigned certificate object.
   var unsignedCert certificate
   unsignedCert.newNoSig(leafData.Bytes())
   {
      // Sign the unsigned certificate's data.
      digest := sha256.Sum256(unsignedCert.encode())
      sigR, sigS, err := ecdsa.Sign(nil, modelKey, digest[:])
      if err != nil {
         return err
      }

      // Safely pad signatures directly into a stack-allocated 64-byte array
      var sign [64]byte
      sigR.FillBytes(sign[:32])
      sigS.FillBytes(sign[32:])

      // Initialize the signature data for the new certificate.
      var signatureData ecdsaSignature
      signatureData.New(sign[:], modelPub)
      // Create FTLV for the signature.
      var value ftlv
      value.New(1, 8, signatureData.encode())
      // Append the signature FTLV to the leaf data.
      leafData.Write(value.encode())
   }
   // Update the unsigned certificate's length and rawData.
   unsignedCert.length = uint32(leafData.Len()) + 16
   unsignedCert.rawData = leafData.Bytes()
   // Update the chain's length, certificate count, and insert the new
   // certificate.
   c.length += unsignedCert.length
   c.certCount += 1
   c.certs = slices.Insert(c.certs, 0, unsignedCert)
   return nil
}

// GenerateLicenseRequest creates the XML body for a license acquisition request.
func (c *Chain) GenerateLicenseRequest(signing *ecdsa.PrivateKey, kid []byte) ([]byte, error) {
   var key xmlKey
   err := key.New()
   if err != nil {
      return nil, err
   }
   cipherData, err := c.cipherData(&key)
   if err != nil {
      return nil, err
   }
   la, err := newLa(key.PublicKey, cipherData, kid)
   if err != nil {
      return nil, err
   }
   laData, err := la.Marshal()
   if err != nil {
      return nil, err
   }
   laDigest := sha256.Sum256(laData)
   signedInfo := SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: Reference{
         Uri:         "#SignedData",
         DigestValue: laDigest[:],
      },
   }
   signedData, err := signedInfo.Marshal()
   if err != nil {
      return nil, err
   }
   signedDigest := sha256.Sum256(signedData)
   sigR, sigS, err := ecdsa.Sign(nil, signing, signedDigest[:])
   if err != nil {
      return nil, err
   }

   // Safely pad signatures directly into a stack-allocated 64-byte array
   var sign [64]byte
   sigR.FillBytes(sign[:32])
   sigS.FillBytes(sign[32:])

   envelope := Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: Body{
         AcquireLicense: &AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: Challenge{
               Challenge: InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    la,
                  Signature: Signature{
                     SignedInfo:     signedInfo,
                     SignatureValue: sign[:],
                  },
               },
            },
         },
      },
   }
   return envelope.Marshal()
}
