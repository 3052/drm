package bcert

import (
   "bytes"
   "encoding/binary"
   "errors"
   "fmt"
)

func parseBasicInfo(data []byte) (*BasicInfo, error) {
   if len(data) < 76 {
      return nil, errors.New("basic info data too short")
   }

   info := &BasicInfo{}
   offset := 0

   copy(info.CertID[:], data[offset:offset+16])
   offset += 16
   info.SecurityLevel = binary.LittleEndian.Uint32(data[offset:])
   offset += 4
   info.Flags = binary.LittleEndian.Uint32(data[offset:])
   offset += 4
   info.Type = binary.LittleEndian.Uint32(data[offset:])
   offset += 4
   info.DigestValue = make([]byte, 32)
   copy(info.DigestValue, data[offset:offset+32])
   offset += 32
   info.ExpirationDate = binary.LittleEndian.Uint32(data[offset:])
   offset += 4
   copy(info.ClientID[:], data[offset:offset+16])

   return info, nil
}

func serializeBasicInfo(buf *bytes.Buffer, info *BasicInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeBasic, FlagMustUnderstand)

   buf.Write(info.CertID[:])
   binary.Write(buf, binary.LittleEndian, info.SecurityLevel)
   binary.Write(buf, binary.LittleEndian, info.Flags)
   binary.Write(buf, binary.LittleEndian, info.Type)
   buf.Write(info.DigestValue)
   binary.Write(buf, binary.LittleEndian, info.ExpirationDate)
   buf.Write(info.ClientID[:])

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseDomainInfo(data []byte) (*DomainInfo, error) {
   if len(data) < 40 {
      return nil, errors.New("domain info data too short")
   }

   info := &DomainInfo{}
   offset := 0

   copy(info.ServiceID[:], data[offset:offset+16])
   offset += 16
   copy(info.AccountID[:], data[offset:offset+16])
   offset += 16
   info.Revision = binary.LittleEndian.Uint32(data[offset:])
   offset += 4

   urlLen := binary.LittleEndian.Uint32(data[offset:])
   offset += 4

   if offset+int(urlLen) > len(data) {
      return nil, errors.New("domain URL length exceeds data")
   }

   if urlLen > 0 {
      info.DomainURL = make([]byte, urlLen)
      copy(info.DomainURL, data[offset:offset+int(urlLen)])
   }

   return info, nil
}

func serializeDomainInfo(buf *bytes.Buffer, info *DomainInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeDomain, FlagMustUnderstand)

   buf.Write(info.ServiceID[:])
   buf.Write(info.AccountID[:])
   binary.Write(buf, binary.LittleEndian, info.Revision)

   urlLen := uint32(len(info.DomainURL))
   binary.Write(buf, binary.LittleEndian, urlLen)
   buf.Write(info.DomainURL)

   if urlLen%4 != 0 {
      buf.Write(make([]byte, 4-(urlLen%4)))
   }

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parsePCInfo(data []byte) (*PCInfo, error) {
   if len(data) < 4 {
      return nil, errors.New("PC info data too short")
   }
   return &PCInfo{SecurityVersion: binary.LittleEndian.Uint32(data)}, nil
}

func serializePCInfo(buf *bytes.Buffer, info *PCInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypePC, FlagMustUnderstand)
   binary.Write(buf, binary.LittleEndian, info.SecurityVersion)
   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseDeviceInfo(data []byte) (*DeviceInfo, error) {
   if len(data) < 12 {
      return nil, errors.New("device info data too short")
   }
   return &DeviceInfo{
      MaxLicenseSize:       binary.LittleEndian.Uint32(data[0:]),
      MaxHeaderSize:        binary.LittleEndian.Uint32(data[4:]),
      MaxLicenseChainDepth: binary.LittleEndian.Uint32(data[8:]),
   }, nil
}

func serializeDeviceInfo(buf *bytes.Buffer, info *DeviceInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeDevice, FlagMustUnderstand)
   binary.Write(buf, binary.LittleEndian, info.MaxLicenseSize)
   binary.Write(buf, binary.LittleEndian, info.MaxHeaderSize)
   binary.Write(buf, binary.LittleEndian, info.MaxLicenseChainDepth)
   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseManufacturerInfo(data []byte) (*ManufacturerInfo, error) {
   if len(data) < 4 {
      return nil, errors.New("manufacturer info data too short")
   }

   info := &ManufacturerInfo{}
   offset := 0
   info.Flags = binary.LittleEndian.Uint32(data[offset:])
   offset += 4

   readString := func() ([]byte, error) {
      if offset+4 > len(data) {
         return nil, errors.New("string length missing")
      }
      strLen := binary.LittleEndian.Uint32(data[offset:])
      offset += 4
      if offset+int(strLen) > len(data) {
         return nil, errors.New("string data truncated")
      }
      str := make([]byte, strLen)
      if strLen > 0 {
         copy(str, data[offset:offset+int(strLen)])
         offset += int(strLen)
         if strLen%4 != 0 {
            offset += 4 - int(strLen%4)
         }
      }
      return str, nil
   }

   var err error
   info.ManufacturerName, err = readString()
   if err != nil {
      return nil, fmt.Errorf("manufacturer name: %w", err)
   }
   info.ModelName, err = readString()
   if err != nil {
      return nil, fmt.Errorf("model name: %w", err)
   }
   info.ModelNumber, err = readString()
   if err != nil {
      return nil, fmt.Errorf("model number: %w", err)
   }

   return info, nil
}

func serializeManufacturerInfo(buf *bytes.Buffer, info *ManufacturerInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeManufacturer, 0)

   binary.Write(buf, binary.LittleEndian, info.Flags)

   writeStr := func(data []byte) {
      strLen := uint32(len(data))
      binary.Write(buf, binary.LittleEndian, strLen)
      buf.Write(data)
      if strLen%4 != 0 {
         buf.Write(make([]byte, 4-(strLen%4)))
      }
   }

   writeStr(info.ManufacturerName)
   writeStr(info.ModelName)
   writeStr(info.ModelNumber)

   updateObjLength(buf, lengthPos, objStart)
   return nil
}
