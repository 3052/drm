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
   "encoding/hex"
   "errors"
   "github.com/emmansun/gmsm/padding"
   "slices"
   "strings"
)

// Object Flags
const (
   ObjFlagEmpty          = 0x0000
   ObjFlagMustUnderstand = 0x0001
   ObjFlagContainer      = 0x0002
)

// Object Types
const (
   ObjTypeBasic            = 0x0001
   ObjTypeDomain           = 0x0002
   ObjTypePc               = 0x0003
   ObjTypeDevice           = 0x0004
   ObjTypeFeature          = 0x0005
   ObjTypeKey              = 0x0006
   ObjTypeManufacturer     = 0x0007
   ObjTypeSignature        = 0x0008
   ObjTypeSilverlight      = 0x0009
   ObjTypeMetering         = 0x000a
   ObjTypeExtDataSignKey   = 0x000b
   ObjTypeExtDataContainer = 0x000c
   ObjTypeExtDataSignature = 0x000d
   ObjTypeExtDataHwid      = 0x000e
   ObjTypeServer           = 0x000f
   ObjTypeSecurityVersion  = 0x0010
   ObjTypeSecurityVersion2 = 0x0011
)

const (
   CertHeaderTag = 0x43455254 // "CERT"
   CertVersion   = 0x00000001
)

const (
   ChainHeaderTag = 0x43484149 // "CHAI"
   ChainVersion   = 0x00000001
)

type ObjectHeader struct {
   Flags    uint16
   Type     uint16
   CbLength uint32
}

type CertHeader struct {
   HeaderTag           uint32 // = CertHeaderTag
   Version             uint32 // = CertVersion
   CbCertificate       uint32
   CbCertificateSigned uint32
}

type CertId struct {
   Rgb [16]byte
}

func (c CertId) String() string {
   return hex.EncodeToString(c.Rgb[:])
}

type ClientId struct {
   Rgb [16]byte
}

func (c ClientId) String() string {
   return hex.EncodeToString(c.Rgb[:])
}

type BasicInfo struct {
   Header         ObjectHeader
   CertificateID  CertId
   SecurityLevel  uint32
   Flags          uint32
   Type           uint32
   DigestValue    [32]byte
   ExpirationDate uint32
   ClientID       ClientId
}

type DeviceInfo struct {
   Header        ObjectHeader
   CbMaxLicense  uint32
   CbMaxHeader   uint32
   MaxChainDepth uint32
}

type FeatureInfo struct {
   Header            ObjectHeader
   NumFeatureEntries uint32
   FeatureSet        []uint32
}

type CertKey struct {
   Type     uint16
   Length   uint16
   Flags    uint32
   Value    []byte
   UsageSet []uint32
}

type KeyInfo struct {
   Header  ObjectHeader
   NumKeys uint32
   Keys    []CertKey
}

type PaddedString string

func (ps PaddedString) String() string {
   return strings.TrimRight(string(ps), "\x00")
}

type ManufacturerStrings struct {
   ManufacturerName PaddedString
   ModelName        PaddedString
   ModelNumber      PaddedString
}

type ManufacturerInfo struct {
   Header              ObjectHeader
   Flags               uint32
   ManufacturerStrings ManufacturerStrings
}

type SignatureData struct {
   Cb    uint16
   Value []byte
}

type SignatureInfo struct {
   Header          ObjectHeader
   SignatureType   uint16
   SignatureData   SignatureData
   IssuerKeyLength uint32 // bits natively
   IssuerKey       []byte
}

type Certificate struct {
   Header           CertHeader
   BasicInfo        *BasicInfo
   DeviceInfo       *DeviceInfo
   FeatureInfo      *FeatureInfo
   KeyInfo          *KeyInfo
   ManufacturerInfo *ManufacturerInfo
   SignatureInfo    *SignatureInfo

   RecordOrder    []uint16
   UnknownRecords map[uint16][]byte
}

type ChainHeader struct {
   HeaderTag uint32 // = ChainHeaderTag
   Version   uint32 // = ChainVersion
   CbChain   uint32
   Flags     uint32
   Certs     uint32
}

type Chain struct {
   Header       ChainHeader
   Certificates []Certificate
}

func ParseChain(data []byte) (*Chain, error) {
   c := &Chain{}
   if len(data) < 20 {
      return nil, errors.New("chain data too short")
   }

   tag := binary.BigEndian.Uint32(data)
   if tag != ChainHeaderTag {
      return nil, errors.New("failed to find chain magic")
   }
   data = data[4:]

   c.Header.HeaderTag = tag
   c.Header.Version = binary.BigEndian.Uint32(data)
   data = data[4:]

   c.Header.CbChain = binary.BigEndian.Uint32(data)
   data = data[4:]

   c.Header.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]

   certCount := binary.BigEndian.Uint32(data)
   data = data[4:]

   c.Header.Certs = certCount
   c.Certificates = make([]Certificate, certCount)

   for index := uint32(0); index < certCount; index++ {
      var cert Certificate
      bytesRead, err := cert.decode(data)
      if err != nil {
         return nil, err
      }
      c.Certificates[index] = cert
      data = data[bytesRead:]
   }

   return c, nil
}

func (c *Chain) Bytes() []byte {
   var certsData []byte
   for _, cert := range c.Certificates {
      certsData = append(certsData, cert.encode()...)
   }

   length := uint32(20 + len(certsData))

   data := make([]byte, 20)
   binary.BigEndian.PutUint32(data[0:4], ChainHeaderTag)
   binary.BigEndian.PutUint32(data[4:8], c.Header.Version)
   binary.BigEndian.PutUint32(data[8:12], length)
   binary.BigEndian.PutUint32(data[12:16], c.Header.Flags)
   binary.BigEndian.PutUint32(data[16:20], uint32(len(c.Certificates)))

   return append(data, certsData...)
}

func (c *Chain) verify() bool {
   modelBase := c.Certificates[len(c.Certificates)-1].SignatureInfo.IssuerKey
   for index := len(c.Certificates) - 1; index >= 0; index-- {
      valid := c.Certificates[index].verify(modelBase)
      if !valid {
         return false
      }
      modelBase = c.Certificates[index].KeyInfo.Keys[0].Value
   }
   return true
}

func (c *Chain) GenerateLeaf(modelKey, signingKey, encryptKey *ecdsa.PrivateKey) error {
   modelPub, err := publicKeyBytes(modelKey)
   if err != nil {
      return err
   }
   if !bytes.Equal(c.Certificates[0].KeyInfo.Keys[0].Value, modelPub) {
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
   unsignedCert.Header.HeaderTag = CertHeaderTag
   unsignedCert.Header.Version = CertVersion
   unsignedCert.UnknownRecords = make(map[uint16][]byte)

   digest := sha256.Sum256(signPub)

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, ObjTypeBasic)
   unsignedCert.BasicInfo = &BasicInfo{
      Header:         ObjectHeader{Flags: 0, Type: ObjTypeBasic, CbLength: 88},
      SecurityLevel:  c.Certificates[0].BasicInfo.SecurityLevel,
      Type:           2,
      ExpirationDate: 4294967295,
   }
   copy(unsignedCert.BasicInfo.DigestValue[:], digest[:])

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, ObjTypeDevice)
   unsignedCert.DeviceInfo = &DeviceInfo{
      Header:        ObjectHeader{Flags: 0, Type: ObjTypeDevice, CbLength: 20},
      CbMaxLicense:  10240,
      CbMaxHeader:   15360,
      MaxChainDepth: 2,
   }

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, ObjTypeFeature)
   unsignedCert.FeatureInfo = &FeatureInfo{
      Header:            ObjectHeader{Flags: 0, Type: ObjTypeFeature, CbLength: 16},
      NumFeatureEntries: 1,
      FeatureSet:        []uint32{0xD}, // SCALABLE
   }

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, ObjTypeKey)
   keySign := CertKey{
      Type:     1, // ECC 256
      Length:   512,
      Value:    signPub,
      UsageSet: []uint32{1},
   }
   keyEnc := CertKey{
      Type:     1, // ECC 256
      Length:   512,
      Value:    encPub,
      UsageSet: []uint32{2},
   }
   unsignedCert.KeyInfo = &KeyInfo{
      Header:  ObjectHeader{Flags: 0, Type: ObjTypeKey, CbLength: 180},
      NumKeys: 2,
      Keys:    []CertKey{keySign, keyEnc},
   }

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, ObjTypeManufacturer)
   unsignedCert.ManufacturerInfo = c.Certificates[0].ManufacturerInfo

   unsignedCert.RecordOrder = append(unsignedCert.RecordOrder, ObjTypeSignature)
   unsignedCert.SignatureInfo = &SignatureInfo{
      Header:          ObjectHeader{Flags: 1, Type: ObjTypeSignature, CbLength: 82},
      SignatureType:   1,
      SignatureData:   SignatureData{Cb: 64, Value: make([]byte, 64)},
      IssuerKeyLength: uint32(len(modelPub)) * 8, // Bits representation natively
      IssuerKey:       modelPub,
   }

   certData := unsignedCert.encode()
   lengthToSig := binary.BigEndian.Uint32(certData[12:16])
   sigDigest := sha256.Sum256(certData[:lengthToSig])

   sigR, sigS, err := ecdsa.Sign(nil, modelKey, sigDigest[:])
   if err != nil {
      return err
   }

   var sign [64]byte
   sigR.FillBytes(sign[:32])
   sigS.FillBytes(sign[32:])
   unsignedCert.SignatureInfo.SignatureData.Value = sign[:]

   c.Certificates = slices.Insert(c.Certificates, 0, unsignedCert)
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
