package bcert

import (
   "bytes"
   "encoding/binary"
   "errors"
   "fmt"
)

func parseFeatureInfo(data []byte) (*FeatureInfo, error) {
   if len(data) < 4 {
      return nil, errors.New("feature info data too short")
   }

   info := &FeatureInfo{}
   offset := 0
   count := binary.LittleEndian.Uint32(data[offset:])
   offset += 4

   if offset+int(count)*4 > len(data) {
      return nil, errors.New("feature list exceeds data")
   }

   info.Features = make([]uint32, count)
   for i := uint32(0); i < count; i++ {
      info.Features[i] = binary.LittleEndian.Uint32(data[offset:])
      offset += 4
      if info.Features[i] > 0 && info.Features[i] <= 32 {
         info.FeatureSet |= (1 << (info.Features[i] - 1))
      }
   }

   return info, nil
}

func serializeFeatureInfo(buf *bytes.Buffer, info *FeatureInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeFeature, FlagMustUnderstand)

   count := uint32(len(info.Features))
   binary.Write(buf, binary.LittleEndian, count)
   for _, feature := range info.Features {
      binary.Write(buf, binary.LittleEndian, feature)
   }

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func parseKeyInfo(data []byte) (*KeyInfo, error) {
   if len(data) < 4 {
      return nil, errors.New("key info data too short")
   }

   info := &KeyInfo{}
   offset := 0
   info.Entries = binary.LittleEndian.Uint32(data[offset:])
   offset += 4
   info.KeyTypes = make([]KeyType, info.Entries)

   for i := uint32(0); i < info.Entries; i++ {
      if offset+8 > len(data) {
         return nil, errors.New("key type header truncated")
      }

      kt := &info.KeyTypes[i]
      kt.Type = binary.LittleEndian.Uint16(data[offset:])
      offset += 2
      kt.KeyLength = binary.LittleEndian.Uint16(data[offset:])
      offset += 2
      kt.Flags = binary.LittleEndian.Uint32(data[offset:])
      offset += 4

      keyBytes := int(kt.KeyLength) / 8
      if offset+keyBytes > len(data) {
         return nil, errors.New("key value truncated")
      }

      kt.KeyValue = make([]byte, keyBytes)
      copy(kt.KeyValue, data[offset:offset+keyBytes])
      offset += keyBytes

      if keyBytes%4 != 0 {
         offset += 4 - (keyBytes % 4)
      }

      if offset+4 > len(data) {
         return nil, errors.New("key usage count missing")
      }

      usageCount := binary.LittleEndian.Uint32(data[offset:])
      offset += 4

      if offset+int(usageCount)*4 > len(data) {
         return nil, errors.New("key usages truncated")
      }

      kt.KeyUsages = make([]uint32, usageCount)
      for j := uint32(0); j < usageCount; j++ {
         kt.KeyUsages[j] = binary.LittleEndian.Uint32(data[offset:])
         offset += 4
         if kt.KeyUsages[j] > 0 && kt.KeyUsages[j] <= 32 {
            kt.UsageSet |= (1 << (kt.KeyUsages[j] - 1))
         }
      }
   }

   return info, nil
}

func serializeKeyInfo(buf *bytes.Buffer, info *KeyInfo) error {
   objStart := buf.Len()
   lengthPos, _ := writeObjHeader(buf, ObjTypeKey, FlagMustUnderstand)

   binary.Write(buf, binary.LittleEndian, info.Entries)

   for i := uint32(0); i < info.Entries; i++ {
      kt := &info.KeyTypes[i]

      binary.Write(buf, binary.LittleEndian, kt.Type)
      binary.Write(buf, binary.LittleEndian, kt.KeyLength)
      binary.Write(buf, binary.LittleEndian, kt.Flags)
      buf.Write(kt.KeyValue)

      if len(kt.KeyValue)%4 != 0 {
         buf.Write(make([]byte, 4-(len(kt.KeyValue)%4)))
      }

      binary.Write(buf, binary.LittleEndian, uint32(len(kt.KeyUsages)))
      for _, usage := range kt.KeyUsages {
         binary.Write(buf, binary.LittleEndian, usage)
      }
   }

   updateObjLength(buf, lengthPos, objStart)
   return nil
}

func (c *Certificate) GetPublicKey() ([]byte, error) {
   if c.KeyInformation == nil || c.KeyInformation.Entries == 0 {
      return nil, errors.New("no keys in certificate")
   }
   return c.KeyInformation.KeyTypes[0].KeyValue, nil
}

func (c *Certificate) GetKeyByUsage(usage uint32) ([]byte, error) {
   if c.KeyInformation == nil {
      return nil, errors.New("no key information")
   }
   if usage == 0 || usage > 32 {
      return nil, fmt.Errorf("invalid usage value: %d", usage)
   }

   usageBit := uint32(1 << (usage - 1))
   for i := uint32(0); i < c.KeyInformation.Entries; i++ {
      if c.KeyInformation.KeyTypes[i].UsageSet&usageBit != 0 {
         return c.KeyInformation.KeyTypes[i].KeyValue, nil
      }
   }

   return nil, fmt.Errorf("no key found with usage %d", usage)
}

func (c *Certificate) HasFeature(feature uint32) bool {
   if c.FeatureInformation == nil || feature == 0 || feature > 32 {
      return false
   }
   featureBit := uint32(1 << (feature - 1))
   return c.FeatureInformation.FeatureSet&featureBit != 0
}

func (c *Certificate) IsExpired(currentTime uint32) bool {
   if c.BasicInformation == nil || c.BasicInformation.ExpirationDate == 0xFFFFFFFF {
      return false
   }
   return currentTime > c.BasicInformation.ExpirationDate
}
