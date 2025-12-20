package widevine

import "41.neocities.org/protobuf"

// PsshData represents the Widevine-specific protobuf message.
type PsshData struct {
   KeyIds    [][]byte
   ContentId []byte
}

// Marshal serializes the PsshData struct into the protobuf wire format.
func (p *PsshData) Marshal() ([]byte, error) {
   var message protobuf.Message
   for _, keyId := range p.KeyIds {
      if len(keyId) > 0 {
         message = append(message, protobuf.Bytes(2, keyId))
      }
   }
   if len(p.ContentId) > 0 {
      message = append(message, protobuf.Bytes(4, p.ContentId))
   }
   return message.Encode()
}

// Unmarshal parses the protobuf wire format into the PsshData struct.
func (p *PsshData) Unmarshal(data []byte) error {
   var message protobuf.Message
   if err := message.Parse(data); err != nil {
      return err
   }
   p.KeyIds = nil
   p.ContentId = nil

   it := message.Iterator(2)
   for it.Next() {
      if field := it.Field(); field != nil {
         p.KeyIds = append(p.KeyIds, field.Bytes)
      }
   }
   if field, found := message.Field(4); found {
      p.ContentId = field.Bytes
   }
   return nil
}
