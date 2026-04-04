package xml

import (
   "bytes"
   "encoding/binary"
   "encoding/xml"
   "errors"
   "unicode/utf16"
)

// ParsePlayReadyPRO takes a PlayReady Object (PRO) byte slice,
// extracts the XML Record (Type 1), decodes it from UTF-16LE to UTF-8, and parses it.
func ParsePlayReadyPRO(data []byte) (*WrmHeader, error) {
   if len(data) < 10 {
      return nil, errors.New("data too short for PlayReady Object")
   }

   // 1. PlayReady Object (PRO) Length: 4 bytes (Little Endian)
   proLength := int(binary.LittleEndian.Uint32(data[0:4]))
   if proLength > len(data) {
      return nil, errors.New("PRO length exceeds data size")
   }

   // 2. Record Count: 2 bytes (Little Endian)
   recordCount := int(binary.LittleEndian.Uint16(data[4:6]))
   offset := 6

   for i := 0; i < recordCount; i++ {
      if offset+4 > len(data) {
         break
      }

      // Record Type and Length: 2 bytes each (Little Endian)
      recordType := binary.LittleEndian.Uint16(data[offset : offset+2])
      recordLength := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
      offset += 4

      if offset+recordLength > len(data) {
         return nil, errors.New("record length exceeds data size")
      }

      // Type 1 is the Rights Management (RM) Header which contains the XML
      if recordType == 1 {
         xmlData := data[offset : offset+recordLength]
         return parseWrmHeaderXML(xmlData)
      }
      offset += recordLength
   }

   return nil, errors.New("WRMHEADER record not found")
}

func parseWrmHeaderXML(utf16leData []byte) (*WrmHeader, error) {
   if len(utf16leData)%2 != 0 {
      return nil, errors.New("invalid UTF-16LE data length")
   }

   // PlayReady XML uses UTF-16LE. Go's XML parser requires UTF-8.
   // Decode UTF-16LE to UTF-8 before unmarshaling.
   u16s := make([]uint16, len(utf16leData)/2)
   for i := 0; i < len(u16s); i++ {
      u16s[i] = binary.LittleEndian.Uint16(utf16leData[i*2 : i*2+2])
   }

   runes := utf16.Decode(u16s)
   utf8Data := []byte(string(runes))

   // Clean trailing null bytes that might be added to memory boundaries
   utf8Data = bytes.TrimRight(utf8Data, "\x00")

   var header WrmHeader
   err := xml.Unmarshal(utf8Data, &header)
   if err != nil {
      return nil, err
   }

   return &header, nil
}
