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

type certRecord struct {
   Flags            uint16
   Type             uint16
   UnknownData      []byte
   CertificateInfo  *certificateInfo
   DeviceInfo       *device
   Features         *features
   KeyInfo          *keyInfo
   ManufacturerInfo *manufacturer
   SignatureData    *ecdsaSignature
}

func (r *certRecord) decode(data []byte) int {
   r.Flags = binary.BigEndian.Uint16(data)
   n := 2
   r.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   length := binary.BigEndian.Uint32(data[n:])
   n += 4
   valBytes := data[n:][:length-8]
   n += len(valBytes)

   switch r.Type {
   case objTypeBasic:
      info := &certificateInfo{}
      info.decode(valBytes)
      r.CertificateInfo = info
   case objTypeDevice:
      dev := &device{}
      dev.decode(valBytes)
      r.DeviceInfo = dev
   case objTypeFeature:
      feat := &features{}
      feat.decode(valBytes)
      r.Features = feat
   case objTypeKey:
      key := &keyInfo{}
      key.decode(valBytes)
      r.KeyInfo = key
   case objTypeManufacturer:
      man := &manufacturer{}
      man.decode(valBytes)
      r.ManufacturerInfo = man
   case objTypeSignature:
      sig := &ecdsaSignature{}
      sig.decode(valBytes)
      r.SignatureData = sig
   default:
      r.UnknownData = valBytes
   }
   return n
}

func (r *certRecord) encode() []byte {
   // Type 0xFFFF is our custom marker for trailing unformatted padding
   if r.Type == 0xFFFF {
      return r.UnknownData
   }

   var valBytes []byte
   if r.CertificateInfo != nil {
      valBytes = r.CertificateInfo.encode()
   } else if r.DeviceInfo != nil {
      valBytes = r.DeviceInfo.encode()
   } else if r.Features != nil {
      valBytes = r.Features.encode()
   } else if r.KeyInfo != nil {
      valBytes = r.KeyInfo.encode()
   } else if r.ManufacturerInfo != nil {
      valBytes = r.ManufacturerInfo.encode()
   } else if r.SignatureData != nil {
      valBytes = r.SignatureData.encode()
   } else {
      valBytes = r.UnknownData
   }

   data := binary.BigEndian.AppendUint16(nil, r.Flags)
   data = binary.BigEndian.AppendUint16(data, r.Type)
   data = binary.BigEndian.AppendUint32(data, uint32(len(valBytes)+8))
   return append(data, valBytes...)
}

type certificate struct {
   magic   [4]byte
   version uint32
   records []certRecord

   // Helper pointers mapped directly to the structs inside records
   certificateInfo  *certificateInfo
   deviceInfo       *device
   features         *features
   keyInfo          *keyInfo
   manufacturerInfo *manufacturer
   signatureData    *ecdsaSignature
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
   _ = binary.BigEndian.Uint32(data[n:]) // skip lengthToSignature, dynamically evaluated
   n += 4

   certDataLen := int(length - 16)
   certData := data[n : n+certDataLen]
   n += certDataLen

   var n1 int
   for n1 < len(certData) {
      // Safeguard against malformed/unformatted trailing padding zeroes
      if len(certData)-n1 < 8 {
         c.records = append(c.records, certRecord{Type: 0xFFFF, UnknownData: certData[n1:]})
         break
      }
      recLen := binary.BigEndian.Uint32(certData[n1+4 : n1+8])
      if recLen < 8 {
         c.records = append(c.records, certRecord{Type: 0xFFFF, UnknownData: certData[n1:]})
         break
      }

      var record certRecord
      n1 += record.decode(certData[n1:])
      c.records = append(c.records, record)

      switch record.Type {
      case objTypeBasic:
         c.certificateInfo = record.CertificateInfo
      case objTypeDevice:
         c.deviceInfo = record.DeviceInfo
      case objTypeFeature:
         c.features = record.Features
      case objTypeKey:
         c.keyInfo = record.KeyInfo
      case objTypeManufacturer:
         c.manufacturerInfo = record.ManufacturerInfo
      case objTypeSignature:
         c.signatureData = record.SignatureData
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

   for _, record := range c.records {
      if record.Type == objTypeSignature {
         lengthToSignature = uint32(16 + len(raw))
      }
      raw = append(raw, record.encode()...)
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

func (c *certificateInfo) decode(data []byte) {
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

// decode decodes a byte slice into the manufacturer structure.
func (m *manufacturer) decode(data []byte) {
   m.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   n := m.manufacturerName.decode(data)
   data = data[n:]
   n = m.modelName.decode(data)
   data = data[n:]
   m.modelNumber.decode(data)
}

// manufacturerInfo contains a length-prefixed string.
type manufacturerInfo struct {
   length uint32
   value  string
}

// decode decodes a byte slice into the manufacturerInfo structure.
func (m *manufacturerInfo) decode(data []byte) int {
   m.length = binary.BigEndian.Uint32(data)
   n := 4
   // Data is padded to a multiple of 4 bytes.
   padded_length := (m.length + 3) &^ 3
   m.value = string(data[n:][:padded_length])
   n += int(padded_length)
   return n
}

// encode encodes the manufacturerInfo structure into a byte slice.
func (m *manufacturerInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.length)
   return append(data, m.value...)
}
