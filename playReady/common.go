// common.go
package playReady

import "encoding/binary"

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

func UuidOrGuid(data []byte) {
   data[0], data[3] = data[3], data[0]
   data[1], data[2] = data[2], data[1]
   data[4], data[5] = data[5], data[4]
   data[6], data[7] = data[7], data[6]
}

type AuxKey struct {
   Location uint32
   Key      [16]byte
}

func decodeAuxKey(data []byte) (AuxKey, int) {
   a := AuxKey{}
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return a, n
}

type AuxKeys struct {
   Count uint16
   Keys  []AuxKey
}

func (a *AuxKeys) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, a.Count)
   for _, key := range a.Keys {
      data = binary.BigEndian.AppendUint32(data, key.Location)
      data = append(data, key.Key[:]...)
   }
   return data
}

func decodeAuxKeys(data []byte) *AuxKeys {
   a := &AuxKeys{}
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   a.Keys = make([]AuxKey, a.Count)
   for i := range a.Count {
      key, n := decodeAuxKey(data)
      a.Keys[i] = key
      data = data[n:]
   }
   return a
}

type Device struct {
   MaxLicenseSize       uint32
   MaxHeaderSize        uint32
   MaxLicenseChainDepth uint32
}

func (d *Device) initialize() {
   d.MaxLicenseSize = 10240
   d.MaxHeaderSize = 15360
   d.MaxLicenseChainDepth = 2
}

func (d *Device) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, d.MaxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.MaxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.MaxLicenseChainDepth)
}

func decodeDevice(data []byte) *Device {
   d := &Device{}
   d.MaxLicenseSize = binary.BigEndian.Uint32(data)
   d.MaxHeaderSize = binary.BigEndian.Uint32(data[4:])
   d.MaxLicenseChainDepth = binary.BigEndian.Uint32(data[8:])
   return d
}

type Features struct {
   Entries  uint32
   Features []uint32
}

func (f *Features) initialize(Type int) {
   f.Entries = 1
   f.Features = []uint32{uint32(Type)}
}

func (f *Features) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, f.Entries)
   for _, feature := range f.Features {
      data = binary.BigEndian.AppendUint32(data, feature)
   }
   return data
}

func decodeFeatures(data []byte) (*Features, int) {
   f := &Features{}
   f.Entries = binary.BigEndian.Uint32(data)
   n := 4
   for range f.Entries {
      f.Features = append(f.Features, binary.BigEndian.Uint32(data[n:]))
      n += 4
   }
   return f, n
}

type ftlv struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
}

func (f *ftlv) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, f.Flags)
   data = binary.BigEndian.AppendUint16(data, f.Type)
   data = binary.BigEndian.AppendUint32(data, f.Length)
   return append(data, f.Value...)
}

func decodeFtlv(data []byte) (ftlv, int) {
   f := ftlv{}
   f.Flags = binary.BigEndian.Uint16(data)
   n := 2
   f.Type = binary.BigEndian.Uint16(data[n:])
   n += 2
   f.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   f.Value = data[n:][:f.Length-8]
   n += len(f.Value)
   return f, n
}

type Signature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (s *Signature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, s.Type)
   data = binary.BigEndian.AppendUint16(data, s.Length)
   return append(data, s.Data...)
}

func decodeSignature(data []byte) *Signature {
   s := &Signature{}
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Data = data
   return s
}
