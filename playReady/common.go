// common.go
package playReady

import "encoding/binary"

func UuidOrGuid(data []byte) {
   data[0], data[3] = data[3], data[0]
   data[1], data[2] = data[2], data[1]
   data[4], data[5] = data[5], data[4]
   data[6], data[7] = data[7], data[6]
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

func decodePaddedString(data []byte) (PaddedString, int) {
   length := binary.BigEndian.Uint32(data)
   paddedLength := (length + 3) &^ 3
   val := string(data[4 : 4+length])
   return PaddedString(val), int(4 + paddedLength)
}

func encodePaddedString(val PaddedString) []byte {
   length := uint32(len(val))
   paddedLength := (length + 3) &^ 3
   data := make([]byte, int(4+paddedLength))
   binary.BigEndian.PutUint32(data, length)
   copy(data[4:], val)
   return data
}
