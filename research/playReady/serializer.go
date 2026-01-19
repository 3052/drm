package bcert

import (
   "bytes"
   "encoding/binary"
   "errors"
)

func (c *Certificate) Serialize() ([]byte, error) {
   var buf bytes.Buffer

   headerStart := buf.Len()
   binary.Write(&buf, binary.LittleEndian, c.HeaderData.Version)
   lengthPos := buf.Len()
   binary.Write(&buf, binary.LittleEndian, uint32(0))
   signedLengthPos := buf.Len()
   binary.Write(&buf, binary.LittleEndian, uint32(0))

   type objToWrite struct {
      objType uint16
      flags   uint16
      fn      func() error
   }

   objects := []objToWrite{}

   if c.BasicInformation != nil {
      objects = append(objects, objToWrite{ObjTypeBasic, FlagMustUnderstand,
         func() error { return serializeBasicInfo(&buf, c.BasicInformation) }})
   }
   if c.DomainInformation != nil {
      objects = append(objects, objToWrite{ObjTypeDomain, FlagMustUnderstand,
         func() error { return serializeDomainInfo(&buf, c.DomainInformation) }})
   }
   if c.PCInfo != nil {
      objects = append(objects, objToWrite{ObjTypePC, FlagMustUnderstand,
         func() error { return serializePCInfo(&buf, c.PCInfo) }})
   }
   if c.DeviceInformation != nil {
      objects = append(objects, objToWrite{ObjTypeDevice, FlagMustUnderstand,
         func() error { return serializeDeviceInfo(&buf, c.DeviceInformation) }})
   }
   if c.FeatureInformation != nil {
      objects = append(objects, objToWrite{ObjTypeFeature, FlagMustUnderstand,
         func() error { return serializeFeatureInfo(&buf, c.FeatureInformation) }})
   }
   if c.KeyInformation != nil {
      objects = append(objects, objToWrite{ObjTypeKey, FlagMustUnderstand,
         func() error { return serializeKeyInfo(&buf, c.KeyInformation) }})
   }
   if c.ManufacturerInformation != nil {
      objects = append(objects, objToWrite{ObjTypeManufacturer, 0,
         func() error { return serializeManufacturerInfo(&buf, c.ManufacturerInformation) }})
   }
   if c.SilverlightInformation != nil {
      objects = append(objects, objToWrite{ObjTypeSilverlight, FlagMustUnderstand,
         func() error { return serializeSilverlightInfo(&buf, c.SilverlightInformation) }})
   }
   if c.MeteringInformation != nil {
      objects = append(objects, objToWrite{ObjTypeMetering, FlagMustUnderstand,
         func() error { return serializeMeteringInfo(&buf, c.MeteringInformation) }})
   }
   if c.ExDataSigKeyInfo != nil {
      objects = append(objects, objToWrite{ObjTypeExtDataSigKey, 0,
         func() error { return serializeExDataSigKeyInfo(&buf, c.ExDataSigKeyInfo) }})
   }
   if c.SecurityVersion != nil {
      objects = append(objects, objToWrite{ObjTypeSecurityVer, 0,
         func() error { return serializeSecurityVersion(&buf, c.SecurityVersion) }})
   }
   if c.SecurityVersion2 != nil {
      objects = append(objects, objToWrite{ObjTypeSecurityVer2, 0,
         func() error { return serializeSecurityVersion2(&buf, c.SecurityVersion2) }})
   }
   if c.ServerTypeInformation != nil {
      objects = append(objects, objToWrite{ObjTypeServer, FlagMustUnderstand,
         func() error { return serializeServerTypeInfo(&buf, c.ServerTypeInformation) }})
   }
   if c.ExDataContainer != nil {
      objects = append(objects, objToWrite{ObjTypeExtDataContainer, FlagMustUnderstand | FlagContainer,
         func() error { return serializeExtDataContainer(&buf, c.ExDataContainer) }})
   }

   for _, obj := range objects {
      if err := obj.fn(); err != nil {
         return nil, err
      }
   }

   signedEnd := buf.Len()

   if c.SignatureInformation != nil {
      if err := serializeSignatureInfo(&buf, c.SignatureInformation); err != nil {
         return nil, err
      }
   }

   result := buf.Bytes()
   binary.LittleEndian.PutUint32(result[lengthPos:], uint32(len(result)))
   binary.LittleEndian.PutUint32(result[signedLengthPos:], uint32(signedEnd-headerStart))

   return result, nil
}

func (c *CertificateChain) Serialize() ([]byte, error) {
   var buf bytes.Buffer

   binary.Write(&buf, binary.LittleEndian, uint32(BcertChainHeaderTag))
   binary.Write(&buf, binary.LittleEndian, c.Header.Version)
   lengthPos := buf.Len()
   binary.Write(&buf, binary.LittleEndian, uint32(0))
   binary.Write(&buf, binary.LittleEndian, c.Header.Flags)
   binary.Write(&buf, binary.LittleEndian, uint32(len(c.CertHeaders)))

   for _, certHdr := range c.CertHeaders {
      buf.Write(certHdr.RawData)
   }

   result := buf.Bytes()
   binary.LittleEndian.PutUint32(result[lengthPos:], uint32(len(result)))
   return result, nil
}

func writeObjHeader(buf *bytes.Buffer, objType, flags uint16) (int, error) {
   binary.Write(buf, binary.LittleEndian, flags)
   binary.Write(buf, binary.LittleEndian, objType)
   lengthPos := buf.Len()
   binary.Write(buf, binary.LittleEndian, uint32(0))
   return lengthPos, nil
}

func updateObjLength(buf *bytes.Buffer, lengthPos, objStart int) {
   objLength := uint32(buf.Len() - objStart)
   binary.LittleEndian.PutUint32(buf.Bytes()[lengthPos:], objLength)
}

func (c *Certificate) Verify() error {
   if c.BasicInformation == nil {
      return errors.New("missing basic information")
   }
   if c.KeyInformation == nil || c.KeyInformation.Entries == 0 {
      return errors.New("missing key information")
   }
   if c.SignatureInformation == nil {
      return errors.New("missing signature information")
   }
   if len(c.BasicInformation.DigestValue) != SHA256DigestSize {
      return errors.New("invalid digest size")
   }
   return nil
}

func (c *Certificate) RoundTrip() error {
   serialized, err := c.Serialize()
   if err != nil {
      return err
   }
   parsed, err := ParseCertificate(serialized)
   if err != nil {
      return err
   }
   if c.BasicInformation != nil && parsed.BasicInformation != nil {
      if c.BasicInformation.CertID != parsed.BasicInformation.CertID {
         return errors.New("CertID mismatch")
      }
   }
   return nil
}

func (c *CertificateChain) RoundTrip() error {
   serialized, err := c.Serialize()
   if err != nil {
      return err
   }
   _, err = ParseCertificateChain(serialized)
   return err
}
