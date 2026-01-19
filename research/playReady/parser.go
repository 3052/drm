package bcert

import (
   "encoding/binary"
   "errors"
   "fmt"
)

func ParseCertificate(data []byte) (*Certificate, error) {
   if len(data) < 16 {
      return nil, errors.New("certificate data too short")
   }

   cert := &Certificate{RawData: data}
   offset := 0

   if len(data) >= 4 {
      tag := binary.LittleEndian.Uint32(data[offset:])
      if tag == BcertCertHeaderTag {
         offset += 4
      }
   }

   if offset+12 > len(data) {
      return nil, errors.New("certificate header incomplete")
   }

   cert.HeaderData.Version = binary.LittleEndian.Uint32(data[offset:])
   offset += 4
   cert.HeaderData.Length = binary.LittleEndian.Uint32(data[offset:])
   offset += 4
   cert.HeaderData.SignedLength = binary.LittleEndian.Uint32(data[offset:])
   offset += 4

   if cert.HeaderData.Length > uint32(len(data)) {
      return nil, fmt.Errorf("invalid certificate length: %d > %d", cert.HeaderData.Length, len(data))
   }

   signedEnd := int(cert.HeaderData.SignedLength)
   if signedEnd > len(data) {
      signedEnd = len(data)
   }

   for offset < signedEnd && offset+ObjectHeaderLen <= len(data) {
      _ = binary.LittleEndian.Uint16(data[offset:]) // objFlags
      offset += 2
      objType := binary.LittleEndian.Uint16(data[offset:])
      offset += 2
      objLength := binary.LittleEndian.Uint32(data[offset:])
      offset += 4

      objDataStart := offset
      objDataEnd := objDataStart + int(objLength) - ObjectHeaderLen

      if objDataEnd > len(data) {
         return nil, fmt.Errorf("object type 0x%04X extends beyond data", objType)
      }

      objData := data[objDataStart:objDataEnd]
      var err error

      switch objType {
      case ObjTypeBasic:
         cert.BasicInformation, err = parseBasicInfo(objData)
      case ObjTypeDomain:
         cert.DomainInformation, err = parseDomainInfo(objData)
      case ObjTypePC:
         cert.PCInfo, err = parsePCInfo(objData)
      case ObjTypeDevice:
         cert.DeviceInformation, err = parseDeviceInfo(objData)
      case ObjTypeFeature:
         cert.FeatureInformation, err = parseFeatureInfo(objData)
      case ObjTypeKey:
         cert.KeyInformation, err = parseKeyInfo(objData)
      case ObjTypeManufacturer:
         cert.ManufacturerInformation, err = parseManufacturerInfo(objData)
      case ObjTypeSignature:
         cert.SignatureInformation, err = parseSignatureInfo(objData)
      case ObjTypeSilverlight:
         cert.SilverlightInformation, err = parseSilverlightInfo(objData)
      case ObjTypeMetering:
         cert.MeteringInformation, err = parseMeteringInfo(objData)
      case ObjTypeExtDataSigKey:
         cert.ExDataSigKeyInfo, err = parseExDataSigKeyInfo(objData)
      case ObjTypeExtDataContainer:
         cert.ExDataContainer, err = parseExtDataContainer(objData)
      case ObjTypeServer:
         cert.ServerTypeInformation, err = parseServerTypeInfo(objData)
      case ObjTypeSecurityVer:
         cert.SecurityVersion, err = parseSecurityVersion(objData)
      case ObjTypeSecurityVer2:
         cert.SecurityVersion2, err = parseSecurityVersion(objData)
      }

      if err != nil {
         return nil, fmt.Errorf("parsing object type 0x%04X: %w", objType, err)
      }
      offset = objDataEnd
   }

   return cert, nil
}

func ParseCertificateChain(data []byte) (*CertificateChain, error) {
   if len(data) < 20 {
      return nil, errors.New("data too short for certificate chain")
   }

   chain := &CertificateChain{RawData: data}
   offset := 0

   tag := binary.LittleEndian.Uint32(data[offset:])
   if tag == BcertChainHeaderTag {
      offset += 4
      chain.Header.Version = binary.LittleEndian.Uint32(data[offset:])
      offset += 4
      chain.Header.CbChain = binary.LittleEndian.Uint32(data[offset:])
      offset += 4
      chain.Header.Flags = binary.LittleEndian.Uint32(data[offset:])
      offset += 4
      chain.Header.Certs = binary.LittleEndian.Uint32(data[offset:])
      offset += 4
   } else {
      chain.Header.Version = BcertCurrentVersion
      chain.Header.CbChain = uint32(len(data))
      chain.Header.Flags = 0
      chain.Header.Certs = 1
   }

   if chain.Header.Certs > BcertMaxCertsPerChain {
      return nil, fmt.Errorf("too many certificates: %d", chain.Header.Certs)
   }

   chain.CertHeaders = make([]CertHeader, chain.Header.Certs)
   chain.Expiration = 0xFFFFFFFF

   for i := uint32(0); i < chain.Header.Certs; i++ {
      certStart := offset
      if offset+4 <= len(data) && binary.LittleEndian.Uint32(data[offset:]) == BcertCertHeaderTag {
         offset += 4
      }

      if offset+12 > len(data) {
         return nil, fmt.Errorf("certificate %d header incomplete", i)
      }

      hdr := &chain.CertHeaders[i]
      hdr.Index = i
      hdr.Offset = uint32(certStart)
      hdr.HeaderData.Version = binary.LittleEndian.Uint32(data[offset:])
      offset += 4
      hdr.HeaderData.Length = binary.LittleEndian.Uint32(data[offset:])
      offset += 4
      hdr.HeaderData.SignedLength = binary.LittleEndian.Uint32(data[offset:])
      offset += 4

      certEnd := certStart + int(hdr.HeaderData.Length)
      if certEnd > len(data) {
         return nil, fmt.Errorf("certificate %d extends beyond data", i)
      }

      hdr.RawData = data[certStart:certEnd]
      offset = certEnd
   }

   return chain, nil
}
