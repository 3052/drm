package playReady

import (
   "41.neocities.org/drm/playReady/xml"
   "crypto/ecdsa"
   "crypto/sha256"
   "encoding/binary"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func (c *Chain) requestBody(signing EcKey, kid []byte) ([]byte, error) {
   var key xmlKey
   key.New()
   cipherData, err := c.cipherData(&key)
   if err != nil {
      return nil, err
   }
   la := newLa(&key.PublicKey, cipherData, kid)
   laData, err := la.Marshal()
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
   signedData, err := signedInfo.Marshal()
   if err != nil {
      return nil, err
   }
   signedDigest := sha256.Sum256(signedData)
   r, s, err := ecdsa.Sign(Fill('B'), signing[0], signedDigest[:])
   if err != nil {
      return nil, err
   }
   envelope := xml.Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: xml.Body{
         AcquireLicense: &xml.AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: xml.Challenge{
               Challenge: xml.InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    la,
                  Signature: xml.Signature{
                     SignedInfo:     signedInfo,
                     SignatureValue: append(r.Bytes(), s.Bytes()...),
                  },
               },
            },
         },
      },
   }
   return envelope.Marshal()
}

func UuidOrGuid(data []byte) {
   // Data1 (first 4 bytes) - swap endianness in place
   data[0], data[3] = data[3], data[0]
   data[1], data[2] = data[2], data[1]
   // Data2 (next 2 bytes) - swap endianness in place
   data[4], data[5] = data[5], data[4]
   // Data3 (next 2 bytes) - swap endianness in place
   data[6], data[7] = data[7], data[6]
   // Data4 (last 8 bytes) - no change needed, so no operation here
}

type auxKeys struct {
   Count uint16
   Keys  []auxKey
}

type auxKey struct {
   Location uint32
   Key      [16]byte
}

type ftlv struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
}

type xmrType uint16

const (
   outerContainerEntryType                 xmrType = 1
   globalPolicyContainerEntryType          xmrType = 2
   playbackPolicyContainerEntryType        xmrType = 4
   minimumOutputProtectionLevelsEntryType  xmrType = 5
   explicitAnalogVideoProtectionEntryType  xmrType = 7
   analogVideoOPLEntryType                 xmrType = 8
   keyMaterialContainerEntryType           xmrType = 9
   contentKeyEntryType                     xmrType = 10
   signatureEntryType                      xmrType = 11
   serialNumberEntryType                   xmrType = 12
   rightsEntryType                         xmrType = 13
   expirationEntryType                     xmrType = 18
   issueDateEntryType                      xmrType = 19
   meteringEntryType                       xmrType = 22
   gracePeriodEntryType                    xmrType = 26
   sourceIDEntryType                       xmrType = 34
   restrictedSourceIDEntryType             xmrType = 40
   domainIDEntryType                       xmrType = 41
   deviceKeyEntryType                      xmrType = 42
   policyMetadataEntryType                 xmrType = 44
   optimizedContentKeyEntryType            xmrType = 45
   explicitDigitalAudioProtectionEntryType xmrType = 46
   expireAfterFirstUseEntryType            xmrType = 48
   digitalAudioOPLEntryType                xmrType = 49
   revocationInfoVersionEntryType          xmrType = 50
   embeddingBehaviorEntryType              xmrType = 51
   securityLevelEntryType                  xmrType = 52
   moveEnablerEntryType                    xmrType = 55
   uplinkKIDEntryType                      xmrType = 59
   copyPoliciesContainerEntryType          xmrType = 60
   copyCountEntryType                      xmrType = 61
   removalDateEntryType                    xmrType = 80
   auxKeyEntryType                         xmrType = 81
   uplinkXEntryType                        xmrType = 82
   realTimeExpirationEntryType             xmrType = 85
   explicitDigitalVideoProtectionEntryType xmrType = 88
   digitalVideoOPLEntryType                xmrType = 89
   secureStopEntryType                     xmrType = 90
   copyUnknownObjectEntryType              xmrType = 65533
   globalPolicyUnknownObjectEntryType      xmrType = 65533
   playbackUnknownObjectEntryType          xmrType = 65533
   copyUnknownContainerEntryType           xmrType = 65534
   unknownContainersEntryType              xmrType = 65534
   playbackUnknownContainerEntryType       xmrType = 65534
)

type signature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (f Fill) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

type Fill byte

// aesECBHandler performs AES ECB encryption/decryption.
// Encrypts if encrypt is true, decrypts otherwise.
func aesECBHandler(data, key []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

// aesCBCHandler performs AES CBC encryption/decryption with PKCS7 padding.
// Encrypts if encrypt is true, decrypts otherwise.
func aesCBCHandler(data, key, iv []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

// device represents device capabilities.
type device struct {
   maxLicenseSize       uint32
   maxHeaderSize        uint32
   maxLicenseChainDepth uint32
}

// new initializes default device capabilities.
func (d *device) New() {
   d.maxLicenseSize = 10240
   d.maxHeaderSize = 15360
   d.maxLicenseChainDepth = 2
}

// encode encodes device capabilities into a byte slice.
func (d *device) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, d.maxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.maxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.maxLicenseChainDepth)
}

// Decode decodes a byte slice into an AuxKey structure.
func (a *auxKey) decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return n
}

// Encode encodes an FTLV structure into a byte slice.
func (f *ftlv) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

// New initializes an FTLV structure.
func (f *ftlv) New(flags, Type int, value []byte) {
   f.Flags = uint16(flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(value) + 8)
   f.Value = value
}

type ecdsaSignature struct {
   signatureType   uint16
   signatureLength uint16
   SignatureData   []byte // The actual signature bytes
   issuerLength    uint32
   IssuerKey       []byte // The public key of the issuer that signed this
}

// manufacturer represents manufacturer details. Renamed to avoid conflict.
type manufacturer struct {
   flags            uint32
   manufacturerName manufacturerInfo
   modelName        manufacturerInfo
   modelNumber      manufacturerInfo
}

// decode decodes a byte slice into a Signature structure.
func (s *signature) decode(data []byte) {
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Data = data
}

func (s *ecdsaSignature) New(signatureData, signingKey []byte) {
   s.signatureType = 1
   s.signatureLength = uint16(len(signatureData))
   s.SignatureData = signatureData
   s.issuerLength = uint32(len(signingKey))
   s.IssuerKey = signingKey
}

func (s *ecdsaSignature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, s.signatureType)
   data = binary.BigEndian.AppendUint16(data, s.signatureLength)
   data = append(data, s.SignatureData...)
   // The original code multiplied issuerLength by 8, implying a bit length,
   // but the IssuerKey length is in bytes. Assuming this multiplication
   // is specific to how it was serialized for a purpose external to this data structure itself.
   data = binary.BigEndian.AppendUint32(data, s.issuerLength*8)
   return append(data, s.IssuerKey...)
}

// Decode decodes a byte slice into an FTLV structure.
func (f *ftlv) decode(data []byte) int {
   f.Flags = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += len(f.Value)
   return n
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

// encode encodes the manufacturerInfo structure into a byte slice.
func (m *manufacturerInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, m.length)
   return append(data, m.value...)
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

func (s *ecdsaSignature) decode(data []byte) {
   s.signatureType = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.signatureLength = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.SignatureData = data[:s.signatureLength]
   data = data[s.signatureLength:]
   s.issuerLength = binary.BigEndian.Uint32(data)
   data = data[4:]
   s.IssuerKey = data
}

// manufacturerInfo contains a length-prefixed string. Renamed to avoid conflict.
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

// Decode decodes a byte slice into an AuxKeys structure.
func (a *auxKeys) decode(data []byte) {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   a.Keys = make([]auxKey, a.Count)
   for i := range a.Count {
      var key auxKey
      n := key.decode(data)
      a.Keys[i] = key
      data = data[n:]
   }
}
