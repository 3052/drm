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
   c := &Chain{} // single letter 'c' allowed because it is the return variable
   copied := copy(c.magic[:], data)
   if string(c.magic[:]) != "CHAI" {
      return nil, errors.New("failed to find chain magic")
   }
   data = data[copied:]
   c.version = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.length = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.certCount = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.certs = make([]certificate, c.certCount)

   for index := range c.certCount {
      var cert certificate
      bytesRead, err := cert.decode(data)
      if err != nil {
         return nil, err
      }
      c.certs[index] = cert
      data = data[bytesRead:]
   }
   return c, nil
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
   for index := len(c.certs) - 1; index >= 0; index-- {
      // Verify each certificate using the public key of its issuer.
      valid := c.certs[index].verify(modelBase[:])
      if !valid {
         return false
      }
      // The public key of the current certificate becomes the issuer key for
      // the next in the chain.
      modelBase = c.certs[index].keyInfo.keys[0].publicKey[:]
   }
   return true
}

// CreateLeaf creates a new leaf certificate and adds it to the chain.
func (c *Chain) CreateLeaf(modelKey, signingKey, encryptKey *ecdsa.PrivateKey) error {
   modelPub, err := PublicKeyBytes(modelKey)
   if err != nil {
      return err
   }
   if !bytes.Equal(c.certs[0].keyInfo.keys[0].publicKey[:], modelPub) {
      return errors.New("zgpriv not for cert")
   }
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

   var leafData bytes.Buffer

   // Write all unsigned FTLV records
   leafData.Write(createCertInfoFtlv(c.certs[0].certificateInfo.securityLevel, signPub))
   leafData.Write(createDeviceFtlv())
   leafData.Write(createFeatureFtlv())
   leafData.Write(createKeyInfoFtlv(signPub, encPub))
   leafData.Write(createManufacturerFtlv(c.certs[0].manufacturerInfo))

   // Wrap raw buffer data into a temporary unsigned cert to prepare for signing
   var unsignedCert certificate
   unsignedCert.newNoSig(leafData.Bytes())

   // Generate the signature FTLV wrapper
   signatureBytes, err := createSignatureFtlv(unsignedCert.encode(), modelKey, modelPub)
   if err != nil {
      return err
   }

   // Append signature and update final certificate limits
   leafData.Write(signatureBytes)
   unsignedCert.length = uint32(leafData.Len()) + 16
   unsignedCert.rawData = leafData.Bytes()

   // Prepend to chain
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
   cipherOutput, err := c.cipherData(&key)
   if err != nil {
      return nil, err
   }
   laRequest, err := newLa(key.PublicKey, cipherOutput, kid)
   if err != nil {
      return nil, err
   }
   laData, err := laRequest.Marshal()
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
                  La:    laRequest,
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

// createCertInfoFtlv constructs the FTLV for the certificate info (Type 1)
func createCertInfoFtlv(securityLevel uint32, signPub []byte) []byte {
   digest := sha256.Sum256(signPub)
   var info certificateInfo
   info.New(securityLevel, digest[:])

   var value ftlv
   value.New(1, 1, info.encode())
   return value.encode()
}

// createDeviceFtlv constructs the FTLV for the device (Type 4)
func createDeviceFtlv() []byte {
   var device1 device
   device1.New()

   var value ftlv
   value.New(1, 4, device1.encode())
   return value.encode()
}

// createFeatureFtlv constructs the FTLV for the features (Type 5)
func createFeatureFtlv() []byte {
   // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
   feature := features{
      entries:  1,
      features: []uint32{0xD},
   }

   var value ftlv
   value.New(1, 5, feature.encode())
   return value.encode()
}

// createKeyInfoFtlv constructs the FTLV for the keys (Type 6)
func createKeyInfoFtlv(signPub []byte, encPub []byte) []byte {
   var key keyInfo
   key.New(signPub, encPub)

   var value ftlv
   value.New(1, 6, key.encode())
   return value.encode()
}

// createManufacturerFtlv constructs the FTLV for the manufacturer (Type 7)
func createManufacturerFtlv(manufacturerInfo *manufacturer) []byte {
   var value ftlv
   value.New(0, 7, manufacturerInfo.encode())
   return value.encode()
}

// createSignatureFtlv constructs the signed FTLV wrapper (Type 8)
func createSignatureFtlv(certData []byte, modelKey *ecdsa.PrivateKey, modelPub []byte) ([]byte, error) {
   digest := sha256.Sum256(certData)
   sigR, sigS, err := ecdsa.Sign(nil, modelKey, digest[:])
   if err != nil {
      return nil, err
   }

   var sign [64]byte
   sigR.FillBytes(sign[:32])
   sigS.FillBytes(sign[32:])

   var signatureData ecdsaSignature
   signatureData.New(sign[:], modelPub)

   var value ftlv
   value.New(1, 8, signatureData.encode())
   return value.encode(), nil
}
