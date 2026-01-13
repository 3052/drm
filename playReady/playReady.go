package playReady

import (
   "encoding/binary"
   "errors"
)

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

func (a *AuxKey) decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return n
}

type AuxKey struct {
   Location uint32
   Key      [16]byte
}

func (a *AuxKeys) decode(data []byte) {
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   a.Keys = make([]AuxKey, a.Count)
   for i := range a.Count {
      var key AuxKey
      n := key.decode(data)
      a.Keys[i] = key
      data = data[n:]
   }
}

type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
}

func (c *CertFeatures) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint32(data, c.Entries)
   for _, feature := range c.Features {
      data = binary.BigEndian.AppendUint32(data, feature)
   }
   return data
}

func (c *CertFeatures) New(Type uint32) {
   c.Entries = 1
   c.Features = []uint32{Type}
}

func (c *CertFeatures) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.Append(nil))
}

func (c *CertFeatures) size() int {
   n := 4 // entries
   n += 4 * len(c.Features)
   return n
}

// It returns the number of bytes consumed.
func (c *CertFeatures) decode(data []byte) int {
   c.Entries = binary.BigEndian.Uint32(data)
   n := 4
   c.Features = make([]uint32, c.Entries)
   for i := range c.Entries {
      c.Features[i] = binary.BigEndian.Uint32(data[n:])
      n += 4
   }
   return n
}

type CertFeatures struct {
   Entries  uint32
   Features []uint32
}

func (c *CertSignature) decode(data []byte) error {
   c.SignatureType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.SignatureLength = binary.BigEndian.Uint16(data)
   if c.SignatureLength != 64 {
      return errors.New("signature length invalid")
   }
   data = data[2:]
   c.Signature = data[:c.SignatureLength]
   data = data[c.SignatureLength:]
   c.IssuerLength = binary.BigEndian.Uint32(data)
   if c.IssuerLength != 512 {
      return errors.New("issuer length invalid")
   }
   data = data[4:]
   c.IssuerKey = data[:c.IssuerLength/8]
   return nil
}

type CertSignature struct {
   SignatureType   uint16
   SignatureLength uint16
   // The actual signature bytes
   Signature    []byte
   IssuerLength uint32
   // The public key of the issuer that signed this certificate
   IssuerKey []byte
}

func (c *CertSignature) New(signature, modelKey []byte) error {
   c.SignatureType = 1 // required
   c.SignatureLength = 64
   if len(signature) != 64 {
      return errors.New("signature length invalid")
   }
   c.Signature = signature
   c.IssuerLength = 512
   if len(modelKey) != 64 {
      return errors.New("model key length invalid")
   }
   c.IssuerKey = modelKey
   return nil
}

func (c *CertSignature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, c.SignatureType)
   data = binary.BigEndian.AppendUint16(data, c.SignatureLength)
   data = append(data, c.Signature...)
   data = binary.BigEndian.AppendUint32(data, c.IssuerLength)
   return append(data, c.IssuerKey...)
}

func (c *CertSignature) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.encode())
}

func (c *CertSignature) size() int {
   n := 2  // signatureType
   n += 2  // signatureLength
   n += 64 // signature
   n += 4  // issuerLength
   n += 64 // issuerKey
   return n
}

func (c *CertificateInfo) decode(data []byte) {
   c.CertificateId = [16]byte(data)
   data = data[16:]
   c.SecurityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.InfoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Digest = [32]byte(data)
   data = data[32:]
   c.Expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.ClientId = [16]byte(data)
}

func (c *CertificateInfo) encode() []byte {
   data := c.CertificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.SecurityLevel)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.InfoType)
   data = append(data, c.Digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Expiry)
   return append(data, c.ClientId[:]...)
}

func (c *CertificateInfo) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.encode())
}

type CertificateInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   InfoType      uint32
   Digest        [32]byte
   Expiry        uint32
   ClientId      [16]byte // Client ID (can be used for license binding)
}

func (c *CertificateInfo) New(securityLevel uint32, digest []byte) {
   c.Digest = [32]byte(digest)
   // required, Max uint32, effectively never expires
   c.Expiry = 4294967295
   // required
   c.InfoType = 2
   c.SecurityLevel = securityLevel
}

func (e *EccKey) decode(data []byte) {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Value = data
}

type EccKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

func newFtlv(Flag, Type uint16, Value []byte) *Ftlv {
   return &Ftlv{
      Flag:   Flag,
      Type:   Type,
      Length: 8 + uint32(len(Value)),
      Value:  Value,
   }
}

func (f *Ftlv) size() int {
   n := 2 // Flag
   n += 2 // Type
   n += 4 // Length
   n += len(f.Value)
   return n
}

func (f *Ftlv) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint16(data, f.Flag)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

func (f *Ftlv) decode(data []byte) (int, error) {
   f.Flag = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:f.Length]
   n += len(f.Value)
   return n, nil
}

type Ftlv struct {
   Flag   uint16 // this can be 0 or 1
   Type   uint16
   Length uint32
   Value  []byte
}

func (k *KeyData) decode(data []byte) int {
   k.KeyType = binary.BigEndian.Uint16(data)
   n := 2
   k.Length = binary.BigEndian.Uint16(data[n:])
   n += 2
   k.Flags = binary.BigEndian.Uint32(data[n:])
   n += 4
   n += copy(k.PublicKey[:], data[n:])
   n += k.Usage.decode(data[n:])
   return n
}

func (k *KeyData) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint16(data, k.KeyType)
   data = binary.BigEndian.AppendUint16(data, k.Length)
   data = binary.BigEndian.AppendUint32(data, k.Flags)
   data = append(data, k.PublicKey[:]...)
   return k.Usage.Append(data)
}

func (k *KeyData) New(PublicKey []byte, Type uint32) {
   k.Length = 512 // required
   copy(k.PublicKey[:], PublicKey)
   k.Usage.New(Type)
}

func (k *KeyData) size() int {
   n := 2 // keyType
   n += 2 // length
   n += 4 // flags
   n += len(k.PublicKey)
   n += k.Usage.size()
   return n
}

type KeyData struct {
   KeyType   uint16
   Length    uint16
   Flags     uint32
   PublicKey [64]byte // ECDSA P256 public key (X and Y coordinates)
   Usage     CertFeatures
}

func (k *KeyInfo) decode(data []byte) {
   k.Entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   k.Keys = make([]KeyData, k.Entries)
   for i := range k.Entries {
      var key KeyData
      n := key.decode(data)
      k.Keys[i] = key
      data = data[n:] // Advance data slice for the next key
   }
}

type KeyInfo struct {
   Entries uint32 // can be 1 or 2
   Keys    []KeyData
}

func (k *KeyInfo) New(encryptSignKey []byte) {
   k.Entries = 2 // required
   k.Keys = make([]KeyData, 2)
   k.Keys[0].New(encryptSignKey, 1)
   k.Keys[1].New(encryptSignKey, 2)
}

func (k *KeyInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, k.Entries)
   for _, key := range k.Keys {
      data = key.Append(data)
   }
   return data
}

func (k *KeyInfo) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, k.encode())
}

func (k *KeyInfo) size() int {
   n := 4 // entries
   for _, key := range k.Keys {
      n += key.size()
   }
   return n
}

func (l *LicenseSignature) size() int {
   n := 2 // type
   n += 2 // length
   n += len(l.Data)
   return n
}

func (l *LicenseSignature) decode(data []byte) {
   l.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Data = data
}

type LicenseSignature struct {
   Type   uint16
   Length uint16
   Data   []byte
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
   sourceIdEntryType                       xmrType = 34
   restrictedSourceIdEntryType             xmrType = 40
   domainIdEntryType                       xmrType = 41
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
   uplinkKidEntryType                      xmrType = 59
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
