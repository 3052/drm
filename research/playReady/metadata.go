package bcert

import (
   "bytes"
   "encoding/binary"
   "errors"
)

func parseSignatureInfo(data []byte) (*SignatureInfo, error) {
   if len(data) < 4 {
      return nil, errors.New("signature info data too short")
   }

   info := &SignatureInfo{}
   offset := 0

   info.SignatureType = binary.LittleEndian.Uint16(data[offset:])
   offset += 2
   sigLen := binary.LittleEndian.Uint16(data[offset:])
   offset += 2

   if offset+int(sigLen) > len(data) {
      return nil, errors.New("signature truncated")
   }

   info.Signature = make([]byte, sigLen)
   copy(info.Signature, data[offset:offset+int(sigLen)])
   offset += int(sigLen)

   if sigLen%4 != 0 {
      offset += 4 - int(sigLen%4)
   }

   if offset+4 > len(data) {
      return nil, errors.New("issuer key length missing")
   }

   keyLenBits := binary.LittleEndian.Uint32(data[offset:])
   offset += 4
   keyLenBytes := int(keyLenBits) / 8

   if offset+keyLenBytes > len(data) {
      return nil, errors.New("issuer key truncated")
   }

   info.IssuerKey = make([]byte, keyLenBytes)
   copy(info.IssuerKey, data[offset:offset+keyLenBytes])

   return info, nil
}

func serializeSignatureInfo(buf *bytes.Buffer, info *SignatureInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeSignature, FlagMustUnderstand)

   binary.Write(buf, binary.LittleEndian, info.SignatureType)
   sigLen := uint16(len(info.Signature))
   binary.Write(buf, binary.LittleEndian, sigLen)
   buf.Write(info.Signature)

   if sigLen%4 != 0 {
      buf.Write(make([]byte, 4-(sigLen%4)))
   }

   keyLenBits := uint32(len(info.IssuerKey) * 8)
   binary.Write(buf, binary.LittleEndian, keyLenBits)
   buf.Write(info.IssuerKey)

   if len(info.IssuerKey)%4 != 0 {
      buf.Write(make([]byte, 4-(len(info.IssuerKey)%4)))
   }

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseSilverlightInfo(data []byte) (*SilverlightInfo, error) {
   if len(data) < 8 {
      return nil, errors.New("silverlight info data too short")
   }
   return &SilverlightInfo{
      SecurityVersion: binary.LittleEndian.Uint32(data[0:]),
      PlatformID:      binary.LittleEndian.Uint32(data[4:]),
   }, nil
}

func serializeSilverlightInfo(buf *bytes.Buffer, info *SilverlightInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeSilverlight, FlagMustUnderstand)
   binary.Write(buf, binary.LittleEndian, info.SecurityVersion)
   binary.Write(buf, binary.LittleEndian, info.PlatformID)
   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseMeteringInfo(data []byte) (*MeteringInfo, error) {
   if len(data) < 20 {
      return nil, errors.New("metering info data too short")
   }

   info := &MeteringInfo{}
   offset := 0
   copy(info.MeteringID[:], data[offset:offset+16])
   offset += 16

   urlLen := binary.LittleEndian.Uint32(data[offset:])
   offset += 4

   if offset+int(urlLen) > len(data) {
      return nil, errors.New("metering URL truncated")
   }

   if urlLen > 0 {
      info.MeteringURL = make([]byte, urlLen)
      copy(info.MeteringURL, data[offset:offset+int(urlLen)])
   }

   return info, nil
}

func serializeMeteringInfo(buf *bytes.Buffer, info *MeteringInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeMetering, FlagMustUnderstand)

   buf.Write(info.MeteringID[:])
   urlLen := uint32(len(info.MeteringURL))
   binary.Write(buf, binary.LittleEndian, urlLen)
   buf.Write(info.MeteringURL)

   if urlLen%4 != 0 {
      buf.Write(make([]byte, 4-(urlLen%4)))
   }

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseServerTypeInfo(data []byte) (*ServerTypeInfo, error) {
   if len(data) < 4 {
      return nil, errors.New("server type info data too short")
   }
   return &ServerTypeInfo{WarningStartDate: binary.LittleEndian.Uint32(data)}, nil
}

func serializeServerTypeInfo(buf *bytes.Buffer, info *ServerTypeInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeServer, FlagMustUnderstand)
   binary.Write(buf, binary.LittleEndian, info.WarningStartDate)
   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseSecurityVersion(data []byte) (*SecurityVersion, error) {
   if len(data) < 8 {
      return nil, errors.New("security version data too short")
   }
   return &SecurityVersion{
      SecurityVersion: binary.LittleEndian.Uint32(data[0:]),
      PlatformID:      binary.LittleEndian.Uint32(data[4:]),
   }, nil
}

func serializeSecurityVersion(buf *bytes.Buffer, info *SecurityVersion) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeSecurityVer, 0)
   binary.Write(buf, binary.LittleEndian, info.SecurityVersion)
   binary.Write(buf, binary.LittleEndian, info.PlatformID)
   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func serializeSecurityVersion2(buf *bytes.Buffer, info *SecurityVersion) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeSecurityVer2, 0)
   binary.Write(buf, binary.LittleEndian, info.SecurityVersion)
   binary.Write(buf, binary.LittleEndian, info.PlatformID)
   updateObjLength(buf, lengthPos, objStart)
   return nil
}
