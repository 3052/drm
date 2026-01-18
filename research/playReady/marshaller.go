package playready

import (
   "encoding/binary"
   "fmt"
   "sort"
)

// objectForSort is an internal struct used to re-order objects before marshalling.
type objectForSort struct {
   order   uint16
   objType uint16
   flags   uint16
   payload []byte
}

// Marshal encodes the chain back to its binary representation.
func (c *Chain) Marshal() ([]byte, error) {
   w := newWriter()
   _ = w.WriteUint32(ChainHeaderTag)
   _ = w.WriteUint32(c.Header.Version)
   _ = w.WriteUint32(0) // Length placeholder
   _ = w.WriteUint32(c.Header.Flags)
   _ = w.WriteUint32(uint32(len(c.Certificates)))
   for _, cert := range c.Certificates {
      certData, err := cert.Marshal()
      if err != nil {
         return nil, fmt.Errorf("marshalling certificate: %w", err)
      }
      _, _ = w.Write(certData)
   }
   finalBytes := w.Bytes()
   // Update total length in the header (offset 8, length 4)
   binary.LittleEndian.PutUint32(finalBytes[8:12], uint32(len(finalBytes)))
   return finalBytes, nil
}

// Marshal encodes the certificate back to its binary representation.
func (c *Cert) Marshal() ([]byte, error) {
   objectsData, err := marshalCertObjects(c)
   if err != nil {
      return nil, err
   }
   w := newWriter()
   _ = w.WriteUint32(CertHeaderTag)
   _ = w.WriteUint32(c.Header.Version)
   finalLength := uint32(16 + len(objectsData)) // 16 bytes for CERT header
   _ = w.WriteUint32(finalLength)
   _ = w.WriteUint32(c.Header.SignedLength) // Re-use original signed length
   _, _ = w.Write(objectsData)
   return w.Bytes(), nil
}

// marshalCertObjects gathers all objects from a Cert struct, sorts them, and marshals them.
func marshalCertObjects(cert *Cert) ([]byte, error) {
   var objects []objectForSort

   type marshallerInfo struct {
      fn    func() ([]byte, error)
      flags uint16
   }
   knownObjects := make(map[uint16]marshallerInfo)

   if cert.BasicInformation != nil {
      knownObjects[ObjTypeBasic] = marshallerInfo{cert.BasicInformation.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.DomainInformation != nil {
      knownObjects[ObjTypeDomain] = marshallerInfo{cert.DomainInformation.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.PCInfo != nil {
      knownObjects[ObjTypePC] = marshallerInfo{cert.PCInfo.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.DeviceInfo != nil {
      knownObjects[ObjTypeDevice] = marshallerInfo{cert.DeviceInfo.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.FeatureInformation != nil {
      knownObjects[ObjTypeFeature] = marshallerInfo{cert.FeatureInformation.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.KeyInformation != nil {
      knownObjects[ObjTypeKey] = marshallerInfo{cert.KeyInformation.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.ManufacturerInformation != nil {
      knownObjects[ObjTypeManufacturer] = marshallerInfo{cert.ManufacturerInformation.MarshalBinary, ObjFlagNone}
   }
   if cert.SignatureInformation != nil {
      knownObjects[ObjTypeSignature] = marshallerInfo{cert.SignatureInformation.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.SilverlightInformation != nil {
      knownObjects[ObjTypeSilverlight] = marshallerInfo{cert.SilverlightInformation.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.MeteringInformation != nil {
      knownObjects[ObjTypeMetering] = marshallerInfo{cert.MeteringInformation.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.ExDataSigKeyInfo != nil {
      knownObjects[ObjTypeExtDataSignKey] = marshallerInfo{cert.ExDataSigKeyInfo.MarshalBinary, ObjFlagNone}
   }
   if cert.ExDataContainer != nil {
      knownObjects[ObjTypeExtDataContainer] = marshallerInfo{cert.ExDataContainer.MarshalBinary, ObjFlagMustUnderstand | ObjFlagContainerObj}
   }
   if cert.ServerTypeInformation != nil {
      knownObjects[ObjTypeServer] = marshallerInfo{cert.ServerTypeInformation.MarshalBinary, ObjFlagMustUnderstand}
   }
   if cert.SecurityVersion != nil {
      knownObjects[ObjTypeSecurityVersion] = marshallerInfo{cert.SecurityVersion.MarshalBinary, ObjFlagNone}
   }
   if cert.SecurityVersion2 != nil {
      knownObjects[ObjTypeSecurityVersion2] = marshallerInfo{cert.SecurityVersion2.MarshalBinary, ObjFlagNone}
   }

   for objType, m := range knownObjects {
      payload, err := m.fn()
      if err != nil {
         return nil, fmt.Errorf("marshalling obj type 0x%X: %w", objType, err)
      }
      objects = append(objects, objectForSort{
         order:   getObjectSortOrder(objType),
         objType: objType,
         flags:   m.flags,
         payload: payload,
      })
   }

   for _, unk := range cert.UnknownObjects {
      objects = append(objects, objectForSort{order: 0xFFFF, objType: unk.ObjectType, payload: unk.Data, flags: unk.ObjectFlags})
   }

   // Sort objects based on their builder order for round-trip integrity
   sort.Slice(objects, func(i, j int) bool {
      if objects[i].order == objects[j].order {
         return objects[i].objType < objects[j].objType
      }
      return objects[i].order < objects[j].order
   })

   // Write sorted objects to buffer
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

func getObjectSortOrder(objType uint16) uint16 {
   switch objType {
   case ObjTypeBasic:
      return 1
   case ObjTypeDomain, ObjTypePC, ObjTypeDevice, ObjTypeServer, ObjTypeSilverlight, ObjTypeMetering:
      return 2
   case ObjTypeSecurityVersion, ObjTypeSecurityVersion2:
      return 3
   case ObjTypeFeature:
      return 4
   case ObjTypeKey:
      return 5
   case ObjTypeManufacturer:
      return 6
   case ObjTypeExtDataSignKey:
      return 7
   case ObjTypeSignature:
      return 99
   case ObjTypeExtDataContainer:
      return 100
   case ObjTypeExtDataHWID: // within container
      return 101
   case ObjTypeExtDataSignature: // within container
      return 102
   default:
      return 0xFFFF // Unknown objects go to the end
   }
}
