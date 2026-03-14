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

type auxKey struct {
   Location uint32
   Key      [16]byte
}

func decodeAuxKey(data []byte) (auxKey, int) {
   a := auxKey{}
   a.Location = binary.BigEndian.Uint32(data)
   n := 4
   n += copy(a.Key[:], data[n:])
   return a, n
}

type auxKeys struct {
   Count uint16
   Keys  []auxKey
}

func (a *auxKeys) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, a.Count)
   for _, key := range a.Keys {
      data = binary.BigEndian.AppendUint32(data, key.Location)
      data = append(data, key.Key[:]...)
   }
   return data
}

func decodeAuxKeys(data []byte) *auxKeys {
   a := &auxKeys{}
   a.Count = binary.BigEndian.Uint16(data)
   data = data[2:]
   a.Keys = make([]auxKey, a.Count)
   for i := range a.Count {
      key, n := decodeAuxKey(data)
      a.Keys[i] = key
      data = data[n:]
   }
   return a
}

type device struct {
   maxLicenseSize       uint32
   maxHeaderSize        uint32
   maxLicenseChainDepth uint32
}

func (d *device) New() {
   d.maxLicenseSize = 10240
   d.maxHeaderSize = 15360
   d.maxLicenseChainDepth = 2
}

func (d *device) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, d.maxLicenseSize)
   data = binary.BigEndian.AppendUint32(data, d.maxHeaderSize)
   return binary.BigEndian.AppendUint32(data, d.maxLicenseChainDepth)
}

func decodeDevice(data []byte) *device {
   d := &device{}
   d.maxLicenseSize = binary.BigEndian.Uint32(data)
   d.maxHeaderSize = binary.BigEndian.Uint32(data[4:])
   d.maxLicenseChainDepth = binary.BigEndian.Uint32(data[8:])
   return d
}

type features struct {
   entries  uint32
   features []uint32
}

func (f *features) New(Type int) {
   f.entries = 1
   f.features = []uint32{uint32(Type)}
}

func (f *features) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, f.entries)
   for _, feature := range f.features {
      data = binary.BigEndian.AppendUint32(data, feature)
   }
   return data
}

func decodeFeatures(data []byte) (*features, int) {
   f := &features{}
   f.entries = binary.BigEndian.Uint32(data)
   n := 4
   for range f.entries {
      f.features = append(f.features, binary.BigEndian.Uint32(data[n:]))
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

func (f *ftlv) New(flags, Type int, value []byte) {
   f.Flags = uint16(flags)
   f.Type = uint16(Type)
   f.Length = uint32(len(value) + 8)
   f.Value = value
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

type signature struct {
   Type   uint16
   Length uint16
   Data   []byte
}

func (s *signature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, s.Type)
   data = binary.BigEndian.AppendUint16(data, s.Length)
   return append(data, s.Data...)
}

func decodeSignature(data []byte) *signature {
   s := &signature{}
   s.Type = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.Data = data
   return s
}
