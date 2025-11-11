package widevine

import (
   "41.neocities.org/protobuf"
   "fmt"
)

// WidevineHeader holds data parsed from a WidevineCencHeader protobuf message.
// This is a utility struct for users who want to inspect the header contents.
type WidevineHeader struct {
   ContentID []byte
   KeyIDs    [][]byte
}

// ParseWidevineHeader parses the raw WidevineCencHeader protobuf data into a struct
// for inspection. It assumes the input is only the protobuf message.
func ParseWidevineHeader(headerBytes []byte) (*WidevineHeader, error) {
   var msg protobuf.Message
   if err := msg.Parse(headerBytes); err != nil {
      return nil, fmt.Errorf("failed to parse WidevineCencHeader protobuf: %w", err)
   }

   header := &WidevineHeader{}

   // Extract ContentID (optional)
   if field, ok := msg.Field(WidevineCencHeader_ContentId); ok {
      header.ContentID = field.Bytes
   }

   // Extract all KeyIDs
   it := msg.Iterator(WidevineCencHeader_KeyId)
   for it.Next() {
      field := it.Field()
      if field != nil && len(field.Bytes) > 0 {
         header.KeyIDs = append(header.KeyIDs, field.Bytes)
      }
   }

   if len(header.KeyIDs) == 0 {
      return nil, fmt.Errorf("no key IDs found in WidevineCencHeader")
   }

   return header, nil
}
