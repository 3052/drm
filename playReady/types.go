package playReady

import (
   "encoding/binary"
   "math/big"
)

// Ftlv represents a common data structure in PlayReady containing a Flag, Type, Length, and Value.
type Ftlv struct {
   Flag   uint16 // this can be 0 or 1
   Type   uint16
   Length uint32
   Value  []byte
}

// UuidOrGuid swaps the endianness of certain fields within a 16-byte slice to convert between UUID and GUID formats.
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

// decode reads from a byte slice and populates the Ftlv structure.
// It returns the number of bytes consumed.
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

// newFtlv creates and initializes a new Ftlv object.
func newFtlv(Flag, Type uint16, Value []byte) *Ftlv {
   return &Ftlv{
      Flag:   Flag,
      Type:   Type,
      Length: 8 + uint32(len(Value)),
      Value:  Value,
   }
}

// xorKey performs a bitwise XOR operation between two byte slices of equal length.
func xorKey(a, b []byte) []byte {
   if len(a) != len(b) {
      panic("slices have different lengths")
   }
   c := make([]byte, len(a))
   for i := 0; i < len(a); i++ {
      c[i] = a[i] ^ b[i]
   }
   return c
}

// CoordX represents a 32-byte coordinate, typically used for cryptographic keys or IVs.
type CoordX [32]byte

func (c *CoordX) iv() []byte {
   return c[:16]
}

func (c *CoordX) integrity() []byte {
   return c[:16]
}

func (c *CoordX) Key() []byte {
   return c[16:]
}

func (c *CoordX) New(x *big.Int) {
   x.FillBytes(c[:])
}

// ContentKey holds information about an encrypted content key.
type ContentKey struct {
   KeyId      [16]byte
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
}

// decode decodes a byte slice into a ContentKey structure.
func (c *ContentKey) decode(data []byte) {
   c.KeyId = [16]byte(data)
   data = data[16:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data
}

// EccKey represents an Elliptic Curve Cryptography key.
type EccKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

func (e *EccKey) decode(data []byte) {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Value = data
}

// AuxKey represents an auxiliary key used in scalable content key decryption.
type AuxKey struct {
   Location uint32
   Key      [16]byte
}

func (a *AuxKey) decode(data []byte) int {
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return n
}

// AuxKeys is a collection of AuxKey structures.
type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
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

// LicenseSignature holds the signature data for a PlayReady license.
type LicenseSignature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (l *LicenseSignature) decode(data []byte) {
   l.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Data = data
}

func (l *LicenseSignature) size() int {
   n := 2 // type
   n += 2 // length
   n += len(l.Data)
   return n
}

// xmrType defines the type for various entries within an XMR license.
type xmrType uint16

// Constants defining different XMR entry types.
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
