// certificate.go
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

type certificate struct {
   magic            [4]byte
   version          uint32
   certificateInfo  *certificateInfo
   deviceInfo       *device
   features         *features
   keyInfo          *keyInfo
   manufacturerInfo *manufacturer
   signatureData    *ecdsaSignature

   recordOrder    []uint16
   unknownRecords map[uint16][]byte
}

// decode decodes a byte slice into the Cert structure.
func (c *certificate) decode(data []byte) (int, error) {
   n := copy(c.magic[:], data)
   if string(c.magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }
   c.version = binary.BigEndian.Uint32(data[n:])
   n += 4
   length := binary.BigEndian.Uint32(data[n:])
   n += 4
   // skip lengthToSignature, dynamically evaluated
   n += 4

   certDataLen := int(length - 16)
   certData := data[n : n+certDataLen]
   n += certDataLen

   c.unknownRecords = make(map[uint16][]byte)

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

      c.recordOrder = append(c.recordOrder, recType)

      switch recType {
      case objTypeBasic:
         c.certificateInfo = decodeCertificateInfo(valBytes)
      case objTypeDevice:
         c.deviceInfo = decodeDevice(valBytes)
      case objTypeFeature:
         feat, _ := decodeFeatures(valBytes)
         c.features = feat
      case objTypeKey:
         c.keyInfo = decodeKeyInfo(valBytes)
      case objTypeManufacturer:
         c.manufacturerInfo = decodeManufacturer(valBytes)
      case objTypeSignature:
         c.signatureData = decodeEcdsaSignature(valBytes)
      default:
         c.unknownRecords[recType] = valBytes
      }
   }
   return n, nil
}

// verify verifies the signature of the certificate using the provided public key.
func (c *certificate) verify(pubKey []byte) bool {
   if c.signatureData == nil || !bytes.Equal(c.signatureData.IssuerKey, pubKey) {
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

   sign := c.signatureData.SignatureData
   r := new(big.Int).SetBytes(sign[:32])
   s := new(big.Int).SetBytes(sign[32:])

   return ecdsa.Verify(publicKey, signatureDigest[:], r, s)
}

// encode encodes the Cert structure into a byte slice.
func (c *certificate) encode() []byte {
   var raw []byte
   var lengthToSignature uint32

   for _, recType := range c.recordOrder {
      if recType == objTypeSignature {
         lengthToSignature = uint32(16 + len(raw))
      }

      var valBytes []byte
      switch recType {
      case objTypeBasic:
         valBytes = c.certificateInfo.encode()
      case objTypeDevice:
         valBytes = c.deviceInfo.encode()
      case objTypeFeature:
         valBytes = c.features.encode()
      case objTypeKey:
         valBytes = c.keyInfo.encode()
      case objTypeManufacturer:
         valBytes = c.manufacturerInfo.encode()
      case objTypeSignature:
         valBytes = c.signatureData.encode()
      default:
         valBytes = c.unknownRecords[recType]
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
   copy(magicBytes, c.magic[:])
   data := binary.BigEndian.AppendUint32(magicBytes, c.version)
   data = binary.BigEndian.AppendUint32(data, length)
   data = binary.BigEndian.AppendUint32(data, lengthToSignature)
   data = append(data, raw...)
   return data
}

type certificateInfo struct {
   certificateId [16]byte
   securityLevel uint32
   flags         uint32
   infoType      uint32
   digest        [32]byte
   expiry        uint32
   clientId      [16]byte
}

func (c *certificateInfo) encode() []byte {
   data := make([]byte, 0, 80)
   data = append(data, c.certificateId[:]...)
   data = binary.BigEndian.AppendUint32(data, c.securityLevel)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.infoType)
   data = append(data, c.digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.expiry)
   return append(data, c.clientId[:]...)
}

func (c *certificateInfo) New(securityLevel uint32, digest []byte) {
   c.securityLevel = securityLevel
   c.infoType = 2
   copy(c.digest[:], digest)
   c.expiry = 4294967295
}

// decodeCertificateInfo decodes a byte slice into a new certificateInfo structure.
func decodeCertificateInfo(data []byte) *certificateInfo {
   c := &certificateInfo{}
   n := copy(c.certificateId[:], data)
   data = data[n:]
   c.securityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.infoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.digest[:], data)
   data = data[n:]
   c.expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.clientId[:], data)
   return c
}

// manufacturer represents manufacturer details.
type manufacturer struct {
   flags            uint32
   manufacturerName manufacturerInfo
   modelName        manufacturerInfo
   modelNumber      manufacturerInfo
}

// encode encodes the manufacturer structure into a byte slice.
func (m *manufacturer) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.flags)
   data = append(data, m.manufacturerName.encode()...)
   data = append(data, m.modelName.encode()...)
   return append(data, m.modelNumber.encode()...)
}

// decodeManufacturer decodes a byte slice into a new manufacturer structure.
func decodeManufacturer(data []byte) *manufacturer {
   m := &manufacturer{}
   m.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   var n int
   m.manufacturerName, n = decodeManufacturerInfo(data)
   data = data[n:]
   m.modelName, n = decodeManufacturerInfo(data)
   data = data[n:]
   m.modelNumber, _ = decodeManufacturerInfo(data)
   return m
}

// manufacturerInfo contains a length-prefixed string.
type manufacturerInfo struct {
   length uint32
   value  string
}

// decodeManufacturerInfo decodes a byte slice into a manufacturerInfo structure.
func decodeManufacturerInfo(data []byte) (manufacturerInfo, int) {
   m := manufacturerInfo{}
   m.length = binary.BigEndian.Uint32(data)
   n := 4
   // Data is padded to a multiple of 4 bytes.
   padded_length := (m.length + 3) &^ 3
   m.value = string(data[n:][:padded_length])
   n += int(padded_length)
   return m, n
}

// encode encodes the manufacturerInfo structure into a byte slice.
func (m *manufacturerInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.length)
   return append(data, m.value...)
}
