package widevine

import (
   "41.neocities.org/protobuf"
)

// Client represents the device making the license request.
type Client struct {
   Token              []byte
   WidevineCDMVersion string
   OS                 string
   Arch               string
   DeviceModel        string
}

// Build creates a protobuf.Message representing the ClientInfo.
func (c *Client) Build() protobuf.Message {
   var fields protobuf.Message

   if len(c.Token) > 0 {
      fields = append(fields, protobuf.NewBytes(ClientInfo_ClientInfoToken, c.Token))
   }
   if c.WidevineCDMVersion != "" {
      fields = append(fields, protobuf.NewString(ClientInfo_WidevinecdmVersion, c.WidevineCDMVersion))
   }
   if c.OS != "" {
      fields = append(fields, protobuf.NewString(ClientInfo_Os, c.OS))
   }
   if c.Arch != "" {
      fields = append(fields, protobuf.NewString(ClientInfo_Arch, c.Arch))
   }
   if c.DeviceModel != "" {
      fields = append(fields, protobuf.NewString(ClientInfo_DeviceModel, c.DeviceModel))
   }

   return fields
}
