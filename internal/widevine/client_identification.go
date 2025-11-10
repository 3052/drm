package widevine

import (
   "41.neocities.org/protobuf"
)

// ClientIdentification represents the client making the license request.
type ClientIdentification struct {
   // A unique identifier for the client.
   Token []byte
   // Information about the client's capabilities.
   ClientCapabilities *ClientCapabilities
}

// ToProto creates a protobuf.Message from the ClientIdentification struct.
func (ci *ClientIdentification) ToProto() protobuf.Message {
   msg := protobuf.Message{}
   if ci.Token != nil {
      msg = append(msg, protobuf.NewBytes(2, ci.Token))
   }
   if ci.ClientCapabilities != nil {
      msg = append(msg, protobuf.NewMessage(4, ci.ClientCapabilities.ToProto()...))
   }
   return msg
}

// ClientCapabilities defines the capabilities of the client device.
type ClientCapabilities struct {
   // The client's robustness level.
   ClientRobustness string
}

// ToProto creates a protobuf.Message from the ClientCapabilities struct.
func (cc *ClientCapabilities) ToProto() protobuf.Message {
   msg := protobuf.Message{}
   if cc.ClientRobustness != "" {
      msg = append(msg, protobuf.NewString(1, cc.ClientRobustness))
   }
   return msg
}
