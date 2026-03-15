package playReady

import (
   "bytes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
)

// Manufacturer represents manufacturer details.
type Manufacturer struct {
   Flags            uint32
   ManufacturerName string
   ModelName        string
   ModelNumber      string
}

type CertificateInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   InfoType      uint32
   Digest        [32]byte
   Expiry        uint32
   ClientId      [16]byte
}

// decodeCertificateInfo decodes a byte slice into a new CertificateInfo
// structure
func decodeCertificateInfo(data []byte) *CertificateInfo {
   c := &CertificateInfo{}
   n := copy(c.CertificateId[:], data)
   data = data[n:]
   c.SecurityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.InfoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.Digest[:], data)
   data = data[n:]
   c.Expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.ClientId[:], data)
   return c
}

type Certificate struct {
   Magic            [4]byte
   Version          uint32
   CertificateInfo  *CertificateInfo
   DeviceInfo       *Device
   Features         *Features
   KeyInfo          *KeyInfo
   ManufacturerInfo *Manufacturer
   SignatureData    *EcdsaSignature

   RecordOrder    []uint16
   UnknownRecords map[uint16][]byte
}

// Constants for object types within the certificate structure.
const (
   objTypeBasic            = 0x0001
   objTypeDomain           = 0x0002
   objTypePc               = 0x0003
   objTypeDevice           = 0x0004
   objTypeFeature          = 0x0005
   objTypeKey              = 0x0006
   objTypeManufacturer     = 0x0007
   objTypeSignature        = 0x0008
   objTypeSilverlight      = 0x0009
   objTypeMetering         = 0x000A
   objTypeExtDataSignKey   = 0x000B
   objTypeExtDataContainer = 0x000C
   objTypeExtDataSignature = 0x000D
   objTypeExtDataHwid      = 0x000E
   objTypeServer           = 0x000F
   objTypeSecurityVersion  = 0x0010
   objTypeSecurityVersion2 = 0x0011
)

// decodePaddedString decodes a 4-byte length-prefixed string padded to a multiple of 4 bytes.
func decodePaddedString(data []byte) (string, int) {
   length := binary.BigEndian.Uint32(data)
   paddedLength := (length + 3) &^ 3
   val := string(data[4 : 4+length])
   return val, int(4 + paddedLength)
}

// encodePaddedString encodes a string into a 4-byte length-prefixed slice, padded to a multiple of 4 bytes.
func encodePaddedString(val string) []byte {
   length := uint32(len(val))
   paddedLength := (length + 3) &^ 3
   // make auto zero-initializes, giving us our \x00 padding for free
   data := make([]byte, int(4+paddedLength))
   binary.BigEndian.PutUint32(data, length)
   copy(data[4:], val)
   return data
}

// decode decodes a byte slice into the Certificate structure.
func (c *Certificate) decode(data []byte) (int, error) {
   n := copy(c.Magic[:], data)
   if string(c.Magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }
   c.Version = binary.BigEndian.Uint32(data[n:])
   n += 4
   length := binary.BigEndian.Uint32(data[n:])
   n += 4
   // skip lengthToSignature, dynamically evaluated
   n += 4

   certDataLen := int(length - 16)
   certData := data[n : n+certDataLen]
   n += certDataLen

   c.UnknownRecords = make(map[uint16][]byte)

   var n1 int
   for n1 < len(certData) {
      // Safeguard against malformed/unformatted trailing padding zeroes
      if len(certData)-n1 < 8 {
         break
      }

      // skip flags, we re-apply them on encode
      recType := binary.BigEndian.Uint16(certData[n1+2 : n1+4])
      recLen := binary.BigEndian.Uint32(certData[n1+4 : n1+8])

      if recLen < 8 || n1+int(recLen) > len(certData) {
         break
      }

      valBytes := certData[n1+8 : n1+int(recLen)]
      n1 += int(recLen)

      c.RecordOrder = append(c.RecordOrder, recType)

      switch recType {
      case objTypeBasic:
         c.CertificateInfo = decodeCertificateInfo(valBytes)
      case objTypeDevice:
         c.DeviceInfo = decodeDevice(valBytes)
      case objTypeFeature:
         feat, _ := decodeFeatures(valBytes)
         c.Features = feat
      case objTypeKey:
         c.KeyInfo = decodeKeyInfo(valBytes)
      case objTypeManufacturer:
         c.ManufacturerInfo = decodeManufacturer(valBytes)
      case objTypeSignature:
         c.SignatureData = decodeEcdsaSignature(valBytes)
      default:
         c.UnknownRecords[recType] = valBytes
      }
   }
   return n, nil
}

// verify verifies the signature of the certificate using the provided public key.
func (c *Certificate) verify(pubKey []byte) bool {
   if c.SignatureData == nil || !bytes.Equal(c.SignatureData.IssuerKey, pubKey) {
      return false
   }

   encodedKey := [65]byte{4}
   copy(encodedKey[1:], pubKey)

   publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encodedKey[:])
   if err != nil {
      return false
   }

   data := c.encode()
   // Extract the dynamically generated lengthToSignature directly from the header bytes
   lengthToSig := binary.BigEndian.Uint32(data[12:16])
   signatureDigest := sha256.Sum256(data[:lengthToSig])

   sign := c.SignatureData.SignatureData
   r := new(big.Int).SetBytes(sign[:32])
   s := new(big.Int).SetBytes(sign[32:])

   return ecdsa.Verify(publicKey, signatureDigest[:], r, s)
}

// encode encodes the Certificate structure into a byte slice.
func (c *Certificate) encode() []byte {
   var raw []byte
   var lengthToSignature uint32

   for _, recType := range c.RecordOrder {
      if recType == objTypeSignature {
         lengthToSignature = uint32(16 + len(raw))
      }

      var valBytes []byte
      switch recType {
      case objTypeBasic:
         valBytes = c.CertificateInfo.encode()
      case objTypeDevice:
         valBytes = c.DeviceInfo.encode()
      case objTypeFeature:
         valBytes = c.Features.encode()
      case objTypeKey:
         valBytes = c.KeyInfo.encode()
      case objTypeManufacturer:
         valBytes = c.ManufacturerInfo.encode()
      case objTypeSignature:
         valBytes = c.SignatureData.encode()
      default:
         valBytes = c.UnknownRecords[recType]
      }

      flags := uint16(1)
      if recType == objTypeManufacturer {
         flags = 0
      }

      raw = binary.BigEndian.AppendUint16(raw, flags)
      raw = binary.BigEndian.AppendUint16(raw, recType)
      raw = binary.BigEndian.AppendUint32(raw, uint32(len(valBytes)+8))
      raw = append(raw, valBytes...)
   }

   if lengthToSignature == 0 {
      lengthToSignature = uint32(16 + len(raw))
   }

   length := uint32(16 + len(raw))

   magicBytes := make([]byte, 4)
   copy(magicBytes, c.Magic[:])
   data := binary.BigEndian.AppendUint32(magicBytes, c.Version)
   data = binary.BigEndian.AppendUint32(data, length)
   data = binary.BigEndian.AppendUint32(data, lengthToSignature)
   data = append(data, raw...)
   return data
}

func (c *CertificateInfo) encode() []byte {
   data := make([]byte, 0, 80)
   data = append(data, c.CertificateId[:]...)
   data = binary.BigEndian.AppendUint32(data, c.SecurityLevel)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.InfoType)
   data = append(data, c.Digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Expiry)
   return append(data, c.ClientId[:]...)
}

func (c *CertificateInfo) initialize(securityLevel uint32, digest []byte) {
   c.SecurityLevel = securityLevel
   c.InfoType = 2
   copy(c.Digest[:], digest)
   c.Expiry = 4294967295
}

// encode encodes the manufacturer structure into a byte slice.
func (m *Manufacturer) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.Flags)
   data = append(data, encodePaddedString(m.ManufacturerName)...)
   data = append(data, encodePaddedString(m.ModelName)...)
   return append(data, encodePaddedString(m.ModelNumber)...)
}

// decodeManufacturer decodes a byte slice into a new Manufacturer structure.
func decodeManufacturer(data []byte) *Manufacturer {
   m := &Manufacturer{}
   m.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   var n int
   m.ManufacturerName, n = decodePaddedString(data)
   data = data[n:]
   m.ModelName, n = decodePaddedString(data)
   data = data[n:]
   m.ModelNumber, _ = decodePaddedString(data)
   return m
}
