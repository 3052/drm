package widevine

import "41.neocities.org/protobuf"

// WidevinePsshData represents the data structure for building the body
// of a Widevine PSSH box.
type WidevinePsshData struct {
   // KeyIDs is a list of key IDs. Corresponds to the repeated 'key_ids' field.
   KeyIDs [][]byte
   // ContentID corresponds to the optional 'content_id' field.
   ContentID []byte
}

// NewWidevinePsshData creates a new WidevinePsshData object.
// keyIDs or contentID can be nil if not needed.
func NewWidevinePsshData(keyIDs [][]byte, contentID []byte) *WidevinePsshData {
   return &WidevinePsshData{
      KeyIDs:    keyIDs,
      ContentID: contentID,
   }
}

// Encode serializes the WidevinePsshData into the protobuf wire format.
// The resulting byte slice can be used as the 'psshData' parameter for
// NewLicenseRequest.
func (wpd *WidevinePsshData) Encode() ([]byte, error) {
   var message protobuf.Message

   // Add all KeyIDs. Field number is 2.
   for _, keyID := range wpd.KeyIDs {
      if keyID != nil {
         field := protobuf.NewBytes(2, keyID)
         message = append(message, field)
      }
   }

   // Add ContentID if it exists. Field number is 4.
   if len(wpd.ContentID) > 0 {
      field := protobuf.NewBytes(4, wpd.ContentID)
      message = append(message, field)
   }

   return message.Encode()
}
