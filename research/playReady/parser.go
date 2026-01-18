package playready

import (
   "fmt"
   "io"
)

func parseChain(chain *Chain) error {
   r := newReader(chain.RawData)
   chain.Header = &ChainExtendedHeader{}

   headerTag, err := r.ReadUint32()
   if err != nil || headerTag != ChainHeaderTag {
      return ErrInvalidChainHeader
   }
   chain.Header.Version, err = r.ReadUint32()
   if err != nil {
      return err
   }
   chain.Header.Length, err = r.ReadUint32()
   if err != nil {
      return err
   }
   chain.Header.Flags, err = r.ReadUint32()
   if err != nil {
      return err
   }
   chain.Header.Certs, err = r.ReadUint32()
   if err != nil {
      return err
   }

   chain.Certificates = make([]*Cert, 0, chain.Header.Certs)
   offset := 20 // Size of chain header
   for i := uint32(0); i < chain.Header.Certs; i++ {
      if offset >= len(chain.RawData) {
         return ErrUnexpectedEndOfData
      }
      certData := chain.RawData[offset:]
      cert := &Cert{RawData: certData}
      if err := parseCert(cert); err != nil {
         return fmt.Errorf("parsing certificate %d: %w", i, err)
      }
      chain.Certificates = append(chain.Certificates, cert)
      // Correct the raw data slice to be a view only of this certificate's data
      cert.RawData = chain.RawData[offset : offset+int(cert.Header.Length)]
      offset += int(cert.Header.Length)
   }
   return nil
}

func parseCert(cert *Cert) error {
   r := newReader(cert.RawData)
   cert.Header = &ExtendedHeader{}

   headerTag, err := r.ReadUint32()
   if err != nil || headerTag != CertHeaderTag {
      return ErrInvalidCertHeader
   }
   cert.Header.Version, err = r.ReadUint32()
   if err != nil {
      return err
   }
   cert.Header.Length, err = r.ReadUint32()
   if err != nil {
      return err
   }
   cert.Header.SignedLength, err = r.ReadUint32()
   if err != nil {
      return err
   }

   if len(cert.RawData) < int(cert.Header.Length) {
      return ErrObjectTooLarge
   }
   objectsData := cert.RawData[16:cert.Header.Length]
   return unmarshalObjects(objectsData, cert)
}

func unmarshalObjects(data []byte, cert *Cert) error {
   r := newReader(data)
   for r.Len() > 8 { // Minimum object header size is 8
      objType, flags, length, err := readObjectHeader(r)
      if err != nil {
         return err
      }
      objData, err := r.ReadBytes(int(length))
      if err != nil {
         return err
      }

      err = assignObjectToCert(cert, objType, objData)
      if err != nil {
         if err == ErrUnknownObjectType { // If it's unknown, store it.
            cert.UnknownObjects = append(cert.UnknownObjects, &UnknownObject{objType, flags, objData})
         } else {
            return fmt.Errorf("unmarshaling object type 0x%04X: %w", objType, err)
         }
      }

      // Align to 4-byte boundary for the next object
      padding := (4 - (length % 4)) % 4
      if r.Len() >= int(padding) {
         _, _ = r.Seek(int64(padding), io.SeekCurrent)
      }
   }
   return nil
}

func readObjectHeader(r *reader) (objType uint16, flags uint16, length uint32, err error) {
   objType, err = r.ReadUint16()
   if err != nil {
      return
   }
   flags, err = r.ReadUint16()
   if err != nil {
      return
   }
   length, err = r.ReadUint32()
   if err != nil {
      return
   }
   return
}

func assignObjectToCert(cert *Cert, objType uint16, data []byte) error {
   var unmarshalFunc func([]byte) error

   switch objType {
   case ObjTypeBasic:
      cert.BasicInformation = new(BasicInfo)
      unmarshalFunc = cert.BasicInformation.UnmarshalBinary
   case ObjTypeKey:
      cert.KeyInformation = new(KeyInfo)
      unmarshalFunc = cert.KeyInformation.UnmarshalBinary
   case ObjTypeSignature:
      cert.SignatureInformation = new(SignatureInfo)
      unmarshalFunc = cert.SignatureInformation.UnmarshalBinary
   case ObjTypeManufacturer:
      cert.ManufacturerInformation = new(ManufacturerInfo)
      unmarshalFunc = cert.ManufacturerInformation.UnmarshalBinary
   case ObjTypeFeature:
      cert.FeatureInformation = new(FeatureInfo)
      unmarshalFunc = cert.FeatureInformation.UnmarshalBinary
   case ObjTypeDomain:
      cert.DomainInformation = new(DomainInfo)
      unmarshalFunc = cert.DomainInformation.UnmarshalBinary
   case ObjTypePC:
      cert.PCInfo = new(PCInfo)
      unmarshalFunc = cert.PCInfo.UnmarshalBinary
   case ObjTypeDevice:
      cert.DeviceInfo = new(DeviceInfo)
      unmarshalFunc = cert.DeviceInfo.UnmarshalBinary
   case ObjTypeSilverlight:
      cert.SilverlightInformation = new(SilverlightInfo)
      unmarshalFunc = cert.SilverlightInformation.UnmarshalBinary
   case ObjTypeMetering:
      cert.MeteringInformation = new(MeteringInfo)
      unmarshalFunc = cert.MeteringInformation.UnmarshalBinary
   case ObjTypeExtDataContainer:
      cert.ExDataContainer = new(ExtendedDataContainer)
      unmarshalFunc = cert.ExDataContainer.UnmarshalBinary
   case ObjTypeExtDataSignKey:
      cert.ExDataSigKeyInfo = new(ExDataSigKeyInfo)
      unmarshalFunc = cert.ExDataSigKeyInfo.UnmarshalBinary
   case ObjTypeServer:
      cert.ServerTypeInformation = new(ServerTypeInfo)
      unmarshalFunc = cert.ServerTypeInformation.UnmarshalBinary
   case ObjTypeSecurityVersion:
      cert.SecurityVersion = new(SecurityVersion)
      unmarshalFunc = cert.SecurityVersion.UnmarshalBinary
   case ObjTypeSecurityVersion2:
      cert.SecurityVersion2 = new(SecurityVersion2)
      unmarshalFunc = cert.SecurityVersion2.UnmarshalBinary
   default:
      return ErrUnknownObjectType // Signal to caller to handle as unknown
   }

   // The nil check that was here is unreachable because of the default
   // case in the switch above, so it has been removed.

   return unmarshalFunc(data)
}

func assignObjectToContainer(container *ExtendedDataContainer, objType uint16, data []byte) error {
   var err error
   switch objType {
   case ObjTypeExtDataHWID:
      container.HwidRecord = new(HWID)
      err = container.HwidRecord.UnmarshalBinary(data)
   case ObjTypeExtDataSignature:
      container.ExDataSignatureInformation = new(ExtDataSigInfo)
      err = container.ExDataSignatureInformation.UnmarshalBinary(data)
   default:
      unk := &UnknownObject{ObjectType: objType, Data: data}
      container.ExtendedData = append(container.ExtendedData, unk)
   }
   return err
}
