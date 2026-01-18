package playready

import (
   "io"
)

func (o *BasicInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.CertID, err = r.ReadID()
   if err != nil {
      return err
   }
   o.SecurityLevel, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.Flags, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.Type, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.DigestValue, err = r.ReadBytes(32)
   if err != nil {
      return err
   }
   o.ExpirationDate, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.ClientID, err = r.ReadID()
   if err != nil {
      return err
   }
   return nil
}

func (o *DomainInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.ServiceID, err = r.ReadID()
   if err != nil {
      return err
   }
   o.AccountID, err = r.ReadID()
   if err != nil {
      return err
   }
   o.Revision, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.DomainURL, err = r.ReadByteArray()
   if err != nil {
      return err
   }
   return nil
}

func (o *PCInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)

   val, err := r.ReadUint32()
   if err != nil {
      return err
   }
   o.SecurityVersion = val
   return nil
}

func (o *DeviceInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.MaxLicenseSize, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.MaxHeaderSize, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.MaxLicenseChainDepth, err = r.ReadUint32()
   if err != nil {
      return err
   }
   return nil
}

func (o *SilverlightInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.SecurityVersion, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.PlatformID, err = r.ReadUint32()
   if err != nil {
      return err
   }
   return nil
}

func (o *ServerTypeInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)

   val, err := r.ReadUint32()
   if err != nil {
      return err
   }
   o.WarningStartDate = val
   return nil
}

func (o *MeteringInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.MeteringID, err = r.ReadID()
   if err != nil {
      return err
   }
   o.MeteringURL, err = r.ReadByteArray()
   if err != nil {
      return err
   }
   return nil
}

func (o *SecurityVersion) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.SecurityVersion, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.PlatformID, err = r.ReadUint32()
   if err != nil {
      return err
   }
   return nil
}

func (o *SecurityVersion2) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.SecurityVersion, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.PlatformID, err = r.ReadUint32()
   if err != nil {
      return err
   }
   return nil
}

func (o *FeatureInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)

   features, err := r.ReadDwordList()
   if err != nil {
      return err
   }
   o.Features = features
   return nil
}

func (o *KeyInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   count, err := r.ReadUint32()
   if err != nil {
      return err
   }
   o.Keys = make([]KeyType, count)
   for i := 0; i < int(count); i++ {
      k := KeyType{}
      k.Type, err = r.ReadUint16()
      if err != nil {
         return err
      }
      k.KeyLength, err = r.ReadUint16()
      if err != nil {
         return err
      }
      k.Flags, err = r.ReadUint32()
      if err != nil {
         return err
      }
      k.KeyValue, err = r.ReadBytes(int(k.KeyLength))
      if err != nil {
         return err
      }
      k.KeyUsages, err = r.ReadDwordList()
      if err != nil {
         return err
      }
      o.Keys[i] = k
   }
   return nil
}

func (o *ManufacturerInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.Flags, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.ManufacturerName, err = r.ReadByteArray()
   if err != nil {
      return err
   }
   o.ModelName, err = r.ReadByteArray()
   if err != nil {
      return err
   }
   o.ModelNumber, err = r.ReadByteArray()
   if err != nil {
      return err
   }
   return nil
}

func (o *ExDataSigKeyInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.Type, err = r.ReadUint16()
   if err != nil {
      return err
   }
   o.KeyLen, err = r.ReadUint16()
   if err != nil {
      return err
   }
   o.Flags, err = r.ReadUint32()
   if err != nil {
      return err
   }
   o.KeyValue, err = r.ReadBytes(int(o.KeyLen))
   if err != nil {
      return err
   }
   return nil
}

func (o *SignatureInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.SignatureType, err = r.ReadUint16()
   if err != nil {
      return err
   }
   o.Signature, err = r.ReadByteArray16()
   if err != nil {
      return err
   }

   if r.Len() > 0 {
      o.IssuerKey, err = r.ReadByteArray()
      if err != nil {
         return err
      }
   }
   return nil
}

func (o *HWID) UnmarshalBinary(d []byte) error {
   r := newReader(d)

   data, err := r.ReadByteArray()
   if err != nil {
      return err
   }
   o.Data = data
   return nil
}

func (o *ExtDataSigInfo) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   var err error

   o.SignatureType, err = r.ReadUint16()
   if err != nil {
      return err
   }
   o.Signature, err = r.ReadByteArray16()
   if err != nil {
      return err
   }
   return nil
}

func (o *ExtendedDataContainer) UnmarshalBinary(d []byte) error {
   r := newReader(d)
   for r.Len() > 8 {
      objType, _, length, err := readObjectHeader(r)
      if err != nil {
         return err
      }
      objData, err := r.ReadBytes(int(length))
      if err != nil {
         return err
      }
      if err = assignObjectToContainer(o, objType, objData); err != nil {
         return err
      }

      padding := (4 - (length % 4)) % 4
      if r.Len() >= int(padding) {
         _, _ = r.Seek(int64(padding), io.SeekCurrent)
      }
   }
   return nil
}
