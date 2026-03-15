// common.go
package playReady

import "encoding/binary"

func UuidOrGuid(data []byte) {
   data[0], data[3] = data[3], data[0]
   data[1], data[2] = data[2], data[1]
   data[4], data[5] = data[5], data[4]
   data[6], data[7] = data[7], data[6]
}

type Device struct {
   MaxLicenseSize       uint32
   MaxHeaderSize        uint32
   MaxLicenseChainDepth uint32
}

type Features struct {
   Entries  uint32
   Features []uint32
}

type ftlv struct {
   Flags  uint16
   Type   uint16
   Length uint32
   Value  []byte
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
