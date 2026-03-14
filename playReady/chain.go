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

func ParseChain(data []byte) (*Chain, error) {
   c := &Chain{}
   copied := copy(c.Magic[:], data)
   if string(c.Magic[:]) != "CHAI" {
      return nil, errors.New("failed to find chain magic")
   }
   data = data[copied:]
   c.Version = binary.BigEndian.Uint32(data)
   data = data[4:]
   // length (skipping, dynamically evaluated)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   certCount := binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Certs = make([]Certificate, certCount)

   for index := range certCount {
      var cert Certificate
      bytesRead, err := cert.decode(data)
      if err != nil {
         return nil, err
      }
      c.Certs[index] = cert
      data = data[bytesRead:]
   }
   return c, nil
}

// Bytes encodes the Chain into a byte slice.
func (c *Chain) Bytes() []byte {
   var certsData []byte
   for _, cert := range c.Certs {
      certsData = append(certsData, cert.encode()...)
   }

   magicBytes := make([]byte, 4)
   copy(magicBytes, c.Magic[:])
   data := binary.BigEndian.AppendUint32(magicBytes, c.Version)

   // Chain header is 20 bytes (magic, version, length, flags, certCount)
   length := uint32(20 + len(certsData))
   data = binary.BigEndian.AppendUint32(data, length)

   data = binary.BigEndian.AppendUint32(data, c.Flags)

   certCount := uint32(len(c.Certs))
   data = binary.BigEndian.AppendUint32(data, certCount)

   data = append(data, certsData...)
   return data
}

// verify verifies the entire certificate chain.
func (c *Chain) verify() bool {
   // Start verification with the issuer key of the last certificate in the chain.
   modelBase := c.Certs[len(c.Certs)-1].SignatureData.IssuerKey
   for index := len(c.Certs) - 1; index >= 0; index-- {
      // Verify each certificate using the public key of its issuer.
      valid := c.Certs[index].verify(modelBase[:])
      if !valid {
         return false
      }
      // The public key of the current certificate becomes the issuer key for
      // the next in the chain.
      modelBase = c.Certs[index].KeyInfo.Keys[0].PublicKey[:]
   }
   return true
}

func (c *Chain) GenerateLeaf(modelKey, signingKey, encryptKey *ecdsa.PrivateKey) error {
   modelPub, err := publicKeyBytes(modelKey)
   if err != nil {
      return err
   }
   if !bytes.Equal(c.Certs[0].KeyInfo.Keys[0].PublicKey[:], modelPub) {
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

   var unsignedCert Certificate
   copy(unsignedCert.Magic[:], "CERT")
   unsignedCert.Version = 1
   unsignedCert.UnknownRecords = make(map[uint16][]byte)

   var info CertificateInfo
   digest := sha256.Sum256(signPub)
   info.initialize(c.Certs[0].CertificateInfo.SecurityLevel, digest[:])
   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, objTypeBasic)
   unsignedCert.CertificateInfo = &info

   var dev Device
   dev.initialize()
   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, objTypeDevice)
   unsignedCert.DeviceInfo = &dev

   var feat Features
   feat.initialize(0xD) // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, objTypeFeature)
   unsignedCert.Features = &feat

   var key KeyInfo
   key.initialize(signPub, encPub)
   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, objTypeKey)
   unsignedCert.KeyInfo = &key

   // Reusing model Manufacturer info
   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, objTypeManufacturer)
   unsignedCert.ManufacturerInfo = c.Certs[0].ManufacturerInfo

   // To compute dynamic lengths properly in encode(), we append a dummy signature
   // structure so the exact header bytes can be fully calculated for digest signing.
   var dummySig EcdsaSignature
   dummySig.initialize(make([]byte, 64), modelPub)
   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, objTypeSignature)
   unsignedCert.SignatureData = &dummySig

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

   var signatureData EcdsaSignature
   signatureData.initialize(sign[:], modelPub)

   // Replace the dummy signature with the authentic one
   unsignedCert.SignatureData = &signatureData

   c.Certs = slices.Insert(c.Certs, 0, unsignedCert)

   return nil
}

func (c *Chain) LicenseRequestBytes(signingKey *ecdsa.PrivateKey, kid []byte) ([]byte, error) {
   var key xmlKey
   err := key.initialize()
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
         CertificateChain: c.Bytes(),
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

// Chain represents a chain of certificates.
type Chain struct {
   Magic   [4]byte
   Version uint32
   Flags   uint32
   Certs   []Certificate
}
