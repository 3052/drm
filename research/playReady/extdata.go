package bcert

import (
   "bytes"
   "encoding/binary"
   "errors"
   "fmt"
)

func parseExDataSigKeyInfo(data []byte) (*ExDataSigKeyInfo, error) {
   if len(data) < 8 {
      return nil, errors.New("ex data sig key info data too short")
   }

   info := &ExDataSigKeyInfo{}
   offset := 0
   info.Type = binary.LittleEndian.Uint16(data[offset:])
   offset += 2
   info.KeyLen = binary.LittleEndian.Uint16(data[offset:])
   offset += 2
   info.Flags = binary.LittleEndian.Uint32(data[offset:])
   offset += 4

   keyBytes := int(info.KeyLen) / 8
   if offset+keyBytes > len(data) {
      return nil, errors.New("ex data key value truncated")
   }

   info.KeyValue = make([]byte, keyBytes)
   copy(info.KeyValue, data[offset:offset+keyBytes])
   return info, nil
}

func serializeExDataSigKeyInfo(buf *bytes.Buffer, info *ExDataSigKeyInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeExtDataSigKey, 0)

   binary.Write(buf, binary.LittleEndian, info.Type)
   binary.Write(buf, binary.LittleEndian, info.KeyLen)
   binary.Write(buf, binary.LittleEndian, info.Flags)
   buf.Write(info.KeyValue)

   if len(info.KeyValue)%4 != 0 {
      buf.Write(make([]byte, 4-(len(info.KeyValue)%4)))
   }

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseExtDataContainer(data []byte) (*ExtendedDataContainer, error) {
   container := &ExtendedDataContainer{RawData: make([]byte, len(data))}
   copy(container.RawData, data)

   offset := 0
   for offset+ObjectHeaderLen <= len(data) {
      offset += 2
      objType := binary.LittleEndian.Uint16(data[offset:])
      offset += 2
      objLength := binary.LittleEndian.Uint32(data[offset:])
      offset += 4

      objDataStart := offset
      objDataEnd := objDataStart + int(objLength) - ObjectHeaderLen

      if objDataEnd > len(data) {
         break
      }

      objData := data[objDataStart:objDataEnd]
      var err error

      switch objType {
      case ObjTypeExtDataSig:
         container.ExDataSignatureInformation, err = parseExtDataSigInfo(objData)
      case ObjTypeHWID:
         container.HwidRecord, err = parseHWID(objData)
      }

      if err != nil {
         return nil, err
      }
      offset = objDataEnd
   }

   return container, nil
}

func serializeExtDataContainer(buf *bytes.Buffer, container *ExtendedDataContainer) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeExtDataContainer, FlagMustUnderstand|FlagContainer)

   if container.HwidRecord != nil {
      serializeHWID(buf, container.HwidRecord)
   }
   if container.ExDataSignatureInformation != nil {
      serializeExtDataSigInfo(buf, container.ExDataSignatureInformation)
   }

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseExtDataSigInfo(data []byte) (*ExtDataSigInfo, error) {
   if len(data) < 4 {
      return nil, errors.New("ext data sig info data too short")
   }

   info := &ExtDataSigInfo{}
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
   return info, nil
}

func serializeExtDataSigInfo(buf *bytes.Buffer, info *ExtDataSigInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeExtDataSig, FlagMustUnderstand)

   binary.Write(buf, binary.LittleEndian, info.SignatureType)
   sigLen := uint16(len(info.Signature))
   binary.Write(buf, binary.LittleEndian, sigLen)
   buf.Write(info.Signature)

   if sigLen%4 != 0 {
      buf.Write(make([]byte, 4-(sigLen%4)))
   }

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseHWID(data []byte) (*HWID, error) {
   if len(data) < 4 {
      return nil, errors.New("HWID data too short")
   }

   hwid := &HWID{}
   offset := 0
   dataLen := binary.LittleEndian.Uint32(data[offset:])
   offset += 4

   if offset+int(dataLen) > len(data) {
      return nil, errors.New("HWID data truncated")
   }

   if dataLen > 0 {
      hwid.Data = make([]byte, dataLen)
      copy(hwid.Data, data[offset:offset+int(dataLen)])
   }

   return hwid, nil
}

func serializeHWID(buf *bytes.Buffer, hwid *HWID) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeHWID, 0)

   dataLen := uint32(len(hwid.Data))
   binary.Write(buf, binary.LittleEndian, dataLen)
   buf.Write(hwid.Data)

   if dataLen%4 != 0 {
      buf.Write(make([]byte, 4-(dataLen%4)))
   }

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func (c *CertificateChain) GetCertificate(index uint32) (*Certificate, error) {
   if index >= uint32(len(c.CertHeaders)) {
      return nil, fmt.Errorf("certificate index %d out of range", index)
   }
   return ParseCertificate(c.CertHeaders[index].RawData)
}

func (c *CertificateChain) GetLeafCertificate() (*Certificate, error) {
   return c.GetCertificate(0)
}

func (c *CertificateChain) CertificateCount() int {
   return len(c.CertHeaders)
}
