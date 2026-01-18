package playready

import (
   "sort"
)

func (o *BasicInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteID(o.CertID)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.SecurityLevel)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.Flags)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.Type)
   if err != nil {
      return nil, err
   }
   _, err = w.Write(o.DigestValue)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.ExpirationDate)
   if err != nil {
      return nil, err
   }
   err = w.WriteID(o.ClientID)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *DomainInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteID(o.ServiceID)
   if err != nil {
      return nil, err
   }
   err = w.WriteID(o.AccountID)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.Revision)
   if err != nil {
      return nil, err
   }
   err = w.WriteByteArray(o.DomainURL)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *PCInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint32(o.SecurityVersion)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *DeviceInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint32(o.MaxLicenseSize)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.MaxHeaderSize)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.MaxLicenseChainDepth)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *SilverlightInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint32(o.SecurityVersion)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.PlatformID)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *ServerTypeInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint32(o.WarningStartDate)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *MeteringInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteID(o.MeteringID)
   if err != nil {
      return nil, err
   }
   err = w.WriteByteArray(o.MeteringURL)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *SecurityVersion) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint32(o.SecurityVersion)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.PlatformID)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *SecurityVersion2) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint32(o.SecurityVersion)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.PlatformID)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *FeatureInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteDwordList(o.Features)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *KeyInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint32(uint32(len(o.Keys)))
   if err != nil {
      return nil, err
   }
   for _, k := range o.Keys {
      err = w.WriteUint16(k.Type)
      if err != nil {
         return nil, err
      }
      err = w.WriteUint16(uint16(len(k.KeyValue)))
      if err != nil {
         return nil, err
      }
      err = w.WriteUint32(k.Flags)
      if err != nil {
         return nil, err
      }
      _, err = w.Write(k.KeyValue)
      if err != nil {
         return nil, err
      }
      err = w.WriteDwordList(k.KeyUsages)
      if err != nil {
         return nil, err
      }
   }

   return w.Bytes(), nil
}

func (o *ManufacturerInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint32(o.Flags)
   if err != nil {
      return nil, err
   }
   err = w.WriteByteArray(o.ManufacturerName)
   if err != nil {
      return nil, err
   }
   err = w.WriteByteArray(o.ModelName)
   if err != nil {
      return nil, err
   }
   err = w.WriteByteArray(o.ModelNumber)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *ExDataSigKeyInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint16(o.Type)
   if err != nil {
      return nil, err
   }
   err = w.WriteUint16(uint16(len(o.KeyValue)))
   if err != nil {
      return nil, err
   }
   err = w.WriteUint32(o.Flags)
   if err != nil {
      return nil, err
   }
   _, err = w.Write(o.KeyValue)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *SignatureInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint16(o.SignatureType)
   if err != nil {
      return nil, err
   }
   err = w.WriteByteArray16(o.Signature)
   if err != nil {
      return nil, err
   }
   if len(o.IssuerKey) > 0 {
      err = w.WriteByteArray(o.IssuerKey)
      if err != nil {
         return nil, err
      }
   }

   return w.Bytes(), nil
}

func (o *HWID) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteByteArray(o.Data)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *ExtDataSigInfo) MarshalBinary() ([]byte, error) {
   w := newWriter()

   err := w.WriteUint16(o.SignatureType)
   if err != nil {
      return nil, err
   }
   err = w.WriteByteArray16(o.Signature)
   if err != nil {
      return nil, err
   }

   return w.Bytes(), nil
}

func (o *ExtendedDataContainer) MarshalBinary() ([]byte, error) {
   var objects []objectForSort
   type marshallerInfo struct {
      fn    func() ([]byte, error)
      flags uint16
   }
   knownObjects := make(map[uint16]marshallerInfo)

   if o.HwidRecord != nil {
      knownObjects[ObjTypeExtDataHWID] = marshallerInfo{o.HwidRecord.MarshalBinary, ObjFlagNone}
   }
   if o.ExDataSignatureInformation != nil {
      knownObjects[ObjTypeExtDataSignature] = marshallerInfo{o.ExDataSignatureInformation.MarshalBinary, ObjFlagMustUnderstand}
   }

   for objType, m := range knownObjects {
      payload, err := m.fn()
      if err != nil {
         return nil, err
      }
      objects = append(objects, objectForSort{order: getObjectSortOrder(objType), objType: objType, flags: m.flags, payload: payload})
   }
   for _, unk := range o.ExtendedData {
      objects = append(objects, objectForSort{order: 0xFFFF, objType: unk.ObjectType, payload: unk.Data, flags: unk.ObjectFlags})
   }
   sort.Slice(objects, func(i, j int) bool {
      if objects[i].order == objects[j].order {
         return objects[i].objType < objects[j].objType
      }
      return objects[i].order < objects[j].order
   })

   buf := newWriter()
   for _, obj := range objects {
      _ = buf.WriteUint16(obj.objType)
      _ = buf.WriteUint16(obj.flags)
      _ = buf.WriteUint32(uint32(len(obj.payload)))
      _, _ = buf.Write(obj.payload)
      padding := (4 - (len(obj.payload) % 4)) % 4
      if padding > 0 {
         _, _ = buf.Write(make([]byte, padding))
      }
   }

   return buf.Bytes(), nil
}
