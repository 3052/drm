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
   magic             [4]byte
   version           uint32
   length            uint32
   lengthToSignature uint32
   rawData           []byte
   certificateInfo   *certificateInfo
   features          *features
   keyInfo           *keyInfo
   manufacturerInfo  *manufacturer
   signatureData     *ecdsaSignature
}

// decode decodes a byte slice into the Cert structure.
func (c *certificate) decode(data []byte) (int, error) {
   n := copy(c.magic[:], data)
   if string(c.magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }
   c.version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.length = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.lengthToSignature = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.rawData = data[n:][:c.length-16]
   n += len(c.rawData)
   var n1 int
   for n1 < len(c.rawData) {
      var value ftlv
      n1 += value.decode(c.rawData[n1:])
      switch value.Type {
      case objTypeBasic:
         c.certificateInfo = &certificateInfo{}
         c.certificateInfo.decode(value.Value)
      case objTypeFeature:
         c.features = &features{}
         c.features.decode(value.Value)
      case objTypeKey:
         c.keyInfo = &keyInfo{}
         c.keyInfo.decode(value.Value)
      case objTypeManufacturer:
         c.manufacturerInfo = &manufacturer{}
         c.manufacturerInfo.decode(value.Value)
      case objTypeSignature:
         c.signatureData = &ecdsaSignature{}
         c.signatureData.decode(value.Value)
      }
   }
   return n, nil
}

// verify verifies the signature of the certificate using the provided public key.
func (c *certificate) verify(pubKey []byte) bool {
   // Check if the issuer key in the signature matches the provided public key.
   if !bytes.Equal(c.signatureData.IssuerKey, pubKey) {
      return false
   }
   // Reconstruct the ECDSA public key from the byte slice.
   // We need to prepend 0x04 to indicate uncompressed coordinates for ParseUncompressedPublicKey
   encodedKey := make([]byte, 65)
   encodedKey[0] = 4
   copy(encodedKey[1:], pubKey)

   publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encodedKey)
   if err != nil {
      return false
   }

   // Get the data that was signed (up to lengthToSignature).
   data := c.encode()
   data = data[:c.lengthToSignature]
   signatureDigest := sha256.Sum256(data)
   // Extract R and S components from the signature data.
   sign := c.signatureData.SignatureData
   r := new(big.Int).SetBytes(sign[:32])
   s := new(big.Int).SetBytes(sign[32:])
   // Verify the signature.
   return ecdsa.Verify(publicKey, signatureDigest[:], r, s)
}

// newNoSig initializes a new Cert without signature data.
func (c *certificate) newNoSig(data []byte) {
   copy(c.magic[:], "CERT")
   c.version = 1
   // length = length of raw data + header size (16) + signature size (144)
   c.length = uint32(len(data)) + 16 + 144
   // lengthToSignature = length of raw data + header size (16)
   c.lengthToSignature = uint32(len(data)) + 16
   c.rawData = data
}

// encode encodes the Cert structure into a byte slice.
func (c *certificate) encode() []byte {
   data := c.magic[:]
   data = binary.BigEndian.AppendUint32(data, c.version)
   data = binary.BigEndian.AppendUint32(data, c.length)
   data = binary.BigEndian.AppendUint32(data, c.lengthToSignature)
   return append(data, c.rawData...)
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
   data := c.certificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.securityLevel)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.infoType)
   data = append(data, c.digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.expiry)
   return append(data, c.clientId[:]...)
}

func (c *certificateInfo) New(securityLevel uint32, digest []byte) {
   c.securityLevel = securityLevel
   c.infoType = 2 // Assuming infoType 2 is a standard type
   copy(c.digest[:], digest)
   c.expiry = 4294967295 // Max uint32, effectively never expires
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
