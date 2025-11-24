package widevine

import "41.neocities.org/protobuf"

// PsshData represents the Widevine-specific protobuf message.
type PsshData struct {
   KeyIDs    [][]byte
   ContentID []byte
}

// Marshal serializes the PsshData struct into the protobuf wire format.
func (p *PsshData) Marshal() ([]byte, error) {
   var message protobuf.Message

   // Field 2: KeyIDs (Repeated)
   for _, keyID := range p.KeyIDs {
      if len(keyID) > 0 {
         message = append(message, protobuf.Bytes(2, keyID))
      }
   }

   // Field 4: ContentID (Optional)
   if len(p.ContentID) > 0 {
      message = append(message, protobuf.Bytes(4, p.ContentID))
   }

   return message.Encode()
}

// Unmarshal parses the protobuf wire format into the PsshData struct.
func (p *PsshData) Unmarshal(data []byte) error {
   var message protobuf.Message
   if err := message.Parse(data); err != nil {
      return err
   }

   // Reset fields
   p.KeyIDs = nil
   p.ContentID = nil

   // Field 2: KeyIDs
   it := message.Iterator(2)
   for it.Next() {
      if field := it.Field(); field != nil {
         p.KeyIDs = append(p.KeyIDs, field.Bytes)
      }
   }

   // Field 4: ContentID
   if field, found := message.Field(4); found {
      p.ContentID = field.Bytes
   }

   return nil
}
