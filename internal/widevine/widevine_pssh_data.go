package widevine

import "41.neocities.org/protobuf"

// WidevinePsshData is an intermediate message that wraps the PSSHData.
type WidevinePsshData struct {
   // Corresponds to the 'pssh_data' field.
   PSSHData *PSSHData
}

// ToProto creates a protobuf.Message from the WidevinePsshData struct.
func (wpd *WidevinePsshData) ToProto() protobuf.Message {
   msg := protobuf.Message{}
   if wpd.PSSHData != nil {
      // Field 1: The embedded PSSHData message.
      msg = append(msg, protobuf.NewMessage(1, wpd.PSSHData.ToProto()...))
   }
   return msg
}
