// chain.go
package playReady

import (
   "41.neocities.org/drm/playReady/xml"
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

// Chain represents a chain of certificates.
type Chain struct {
   magic   [4]byte
   version uint32
   flags   uint32
   certs   []certificate
}

func ParseChain(data []byte) (*Chain, error) {
   c := &Chain{}
   copied := copy(c.magic[:], data)
   if string(c.magic[:]) != "CHAI" {
      return nil, errors.New("failed to find chain magic")
   }
   data = data[copied:]
   c.version = binary.BigEndian.Uint32(data)
   data = data[4:]
   // length (skipping, dynamically evaluated)
   data = data[4:]
   c.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   certCount := binary.BigEndian.Uint32(data)
   data = data[4:]
   c.certs = make([]certificate, certCount)

   for index := range certCount {
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
   var certsData []byte
   for _, cert := range c.certs {
      certsData = append(certsData, cert.encode()...)
   }

   magicBytes := make([]byte, 4)
   copy(magicBytes, c.magic[:])
   data := binary.BigEndian.AppendUint32(magicBytes, c.version)

   // Chain header is 20 bytes (magic, version, length, flags, certCount)
   length := uint32(20 + len(certsData))
   data = binary.BigEndian.AppendUint32(data, length)

   data = binary.BigEndian.AppendUint32(data, c.flags)

   certCount := uint32(len(c.certs))
   data = binary.BigEndian.AppendUint32(data, certCount)

   data = append(data, certsData...)
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

func (c *Chain) GenerateLeaf(modelKey, signingKey, encryptKey *ecdsa.PrivateKey) error {
   modelPub, err := publicKeyBytes(modelKey)
   if err != nil {
      return err
   }
   if !bytes.Equal(c.certs[0].keyInfo.keys[0].publicKey[:], modelPub) {
      return errors.New("zgpriv not for cert")
   }
   if !c.verify() {
      return errors.New("cert is not valid")
   }

   signPub, err := publicKeyBytes(signingKey)
   if err != nil {
      return err
   }
   encPub, err := publicKeyBytes(encryptKey)
   if err != nil {
      return err
   }

   var unsignedCert certificate
   copy(unsignedCert.magic[:], "CERT")
   unsignedCert.version = 1
   unsignedCert.unknownRecords = make(map[uint16][]byte)

   var info certificateInfo
   digest := sha256.Sum256(signPub)
   info.New(c.certs[0].certificateInfo.securityLevel, digest[:])
   unsignedCert.recordOrder = append(unsignedCert.recordOrder, objTypeBasic)
   unsignedCert.certificateInfo = &info

   var dev device
   dev.New()
   unsignedCert.recordOrder = append(unsignedCert.recordOrder, objTypeDevice)
   unsignedCert.deviceInfo = &dev

   var feat features
   feat.New(0xD) // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
   unsignedCert.recordOrder = append(unsignedCert.recordOrder, objTypeFeature)
   unsignedCert.features = &feat

   var key keyInfo
   key.New(signPub, encPub)
   unsignedCert.recordOrder = append(unsignedCert.recordOrder, objTypeKey)
   unsignedCert.keyInfo = &key

   // Reusing model Manufacturer info
   unsignedCert.recordOrder = append(unsignedCert.recordOrder, objTypeManufacturer)
   unsignedCert.manufacturerInfo = c.certs[0].manufacturerInfo

   // To compute dynamic lengths properly in encode(), we append a dummy signature
   // structure so the exact header bytes can be fully calculated for digest signing.
   var dummySig ecdsaSignature
   dummySig.New(make([]byte, 64), modelPub)
   unsignedCert.recordOrder = append(unsignedCert.recordOrder, objTypeSignature)
   unsignedCert.signatureData = &dummySig

   certData := unsignedCert.encode()
   lengthToSig := binary.BigEndian.Uint32(certData[12:16])
   sigDigest := sha256.Sum256(certData[:lengthToSig])

   // Sign the properly sized bytes
   sigR, sigS, err := ecdsa.Sign(nil, modelKey, sigDigest[:])
   if err != nil {
      return err
   }

   var sign [64]byte
   sigR.FillBytes(sign[:32])
   sigS.FillBytes(sign[32:])

   var signatureData ecdsaSignature
   signatureData.New(sign[:], modelPub)

   // Replace the dummy signature with the authentic one
   unsignedCert.signatureData = &signatureData

   c.certs = slices.Insert(c.certs, 0, unsignedCert)

   return nil
}

// GenerateLicenseRequest creates the XML body for a license acquisition request.
func (c *Chain) GenerateLicenseRequest(signingKey *ecdsa.PrivateKey, kid []byte) ([]byte, error) {
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
   laData, err := xml.Marshal(laRequest)
   if err != nil {
      return nil, err
   }
   laDigest := sha256.Sum256(laData)
   signedInfo := xml.SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: xml.Reference{
         Uri:         "#SignedData",
         DigestValue: laDigest[:],
      },
   }
   signedData, err := xml.Marshal(signedInfo)
   if err != nil {
      return nil, err
   }
   signedDigest := sha256.Sum256(signedData)
   sigR, sigS, err := ecdsa.Sign(nil, signingKey, signedDigest[:])
   if err != nil {
      return nil, err
   }

   var sign [64]byte
   sigR.FillBytes(sign[:32])
   sigS.FillBytes(sign[32:])

   envelope := xml.Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: xml.Body{
         AcquireLicense: &xml.AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: xml.Challenge{
               Challenge: xml.InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    laRequest,
                  Signature: xml.Signature{
                     SignedInfo:     signedInfo,
                     SignatureValue: sign[:],
                  },
               },
            },
         },
      },
   }
   return xml.Marshal(envelope)
}

func (c *Chain) cipherData(key *xmlKey) ([]byte, error) {
   value := xml.Data{
      CertificateChains: xml.CertificateChains{
         CertificateChain: c.Encode(),
      },
      Features: xml.Features{
         Feature: xml.Feature{"AESCBC"}, // SCALABLE
      },
   }
   data, err := xml.Marshal(value)
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
