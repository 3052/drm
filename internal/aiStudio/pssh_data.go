package widevine

import "41.neocities.org/protobuf"

// EncryptionMethod defines the encryption algorithm.
type EncryptionMethod int32

const (
   EncryptionMethod_UNENCRYPTED EncryptionMethod = 0
   EncryptionMethod_AES_CTR     EncryptionMethod = 1
)

// PSSHData represents the structured data within a Widevine PSSH box,
// corresponding to the 'pssh_data' field.
type PSSHData struct {
   Algorithm EncryptionMethod
   KeyIDs    [][]byte
   Provider  string
   ContentID []byte
}

// ToProto creates a protobuf.Message from the PSSHData struct.
func (pd *PSSHData) ToProto() protobuf.Message {
   msg := protobuf.Message{}
   if pd.Algorithm != 0 {
      msg = append(msg, protobuf.NewVarint(1, uint64(pd.Algorithm)))
   }
   for _, keyID := range pd.KeyIDs {
      // Field 2: Repeated bytes for Key IDs
      msg = append(msg, protobuf.NewBytes(2, keyID))
   }
   if pd.Provider != "" {
      msg = append(msg, protobuf.NewString(3, pd.Provider))
   }
   if pd.ContentID != nil {
      msg = append(msg, protobuf.NewBytes(4, pd.ContentID))
   }
   return msg
}
