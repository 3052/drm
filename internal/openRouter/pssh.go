package widevine

import (
   "41.neocities.org/protobuf"
   "bytes"
   "encoding/binary"
   "fmt"
   "io"
)

// PSSHData holds the parsed information from a Widevine PSSH box.
type PSSHData struct {
   KeyIDs [][]byte
   Data   protobuf.Message // Parsed WidevineCencHeader
}

// ParsePSSH parses a Widevine PSSH box.
// The PSSH box format is:
// 4 bytes: size
// 4 bytes: 'pssh'
// 1 byte: version
// 3 bytes: flags
// 16 bytes: system_id
// [if version > 0]
//
//   4 bytes: key_id_count
//   key_id_count * 16 bytes: key_ids
//
// 4 bytes: data_size
// data_size bytes: data (WidevineCencHeader)
func ParsePSSH(box []byte) (*PSSHData, error) {
   if len(box) < 32 { // Minimum size for a v0 PSSH box
      return nil, fmt.Errorf("pssh box is too small: %d bytes", len(box))
   }

   r := bytes.NewReader(box)

   var size uint32
   if err := binary.Read(r, binary.BigEndian, &size); err != nil {
      return nil, fmt.Errorf("failed to read pssh box size: %w", err)
   }

   typeBytes := make([]byte, 4)
   if _, err := io.ReadFull(r, typeBytes); err != nil {
      return nil, fmt.Errorf("failed to read pssh box type: %w", err)
   }
   if string(typeBytes) != "pssh" {
      return nil, fmt.Errorf("not a pssh box, type: %s", string(typeBytes))
   }

   // assumes the input `box` slice is a single, complete PSSH box.
   offset := 8
   if size == 1 { // 64-bit extended size
      offset += 8
   }
   remainingData := box[offset:]
   r = bytes.NewReader(remainingData)

   version, err := r.ReadByte()
   if err != nil {
      return nil, fmt.Errorf("failed to read version: %w", err)
   }

   // Skip flags
   if _, err := r.Seek(3, 1); err != nil {
      return nil, fmt.Errorf("failed to seek past flags: %w", err)
   }

   systemID := make([]byte, 16)
   if _, err := io.ReadFull(r, systemID); err != nil {
      return nil, fmt.Errorf("failed to read system ID: %w", err)
   }
   if !bytes.Equal(systemID, SystemID) {
      return nil, fmt.Errorf("system ID does not match Widevine")
   }

   var keyIDs [][]byte
   if version > 0 {
      var keyIDCount uint32
      if err := binary.Read(r, binary.BigEndian, &keyIDCount); err != nil {
         return nil, fmt.Errorf("failed to read key ID count: %w", err)
      }
      for i := 0; i < int(keyIDCount); i++ {
         keyID := make([]byte, 16)
         if _, err := io.ReadFull(r, keyID); err != nil {
            return nil, fmt.Errorf("failed to read key ID %d: %w", i, err)
         }
         keyIDs = append(keyIDs, keyID)
      }
   }

   var dataSize uint32
   if err := binary.Read(r, binary.BigEndian, &dataSize); err != nil {
      return nil, fmt.Errorf("failed to read data size: %w", err)
   }

   if r.Len() < int(dataSize) {
      return nil, fmt.Errorf("not enough data for WidevineCencHeader, expected %d, got %d", dataSize, r.Len())
   }

   dataBytes := make([]byte, dataSize)
   if _, err := io.ReadFull(r, dataBytes); err != nil {
      return nil, fmt.Errorf("failed to read data: %w", err)
   }

   var cencHeader protobuf.Message
   if err := cencHeader.Parse(dataBytes); err != nil {
      return nil, fmt.Errorf("failed to parse WidevineCencHeader protobuf: %w", err)
   }

   // If version 0, key IDs are inside the CencHeader
   if version == 0 {
      it := cencHeader.Iterator(WidevineCencHeader_KeyId)
      for it.Next() {
         field := it.Field()
         if field != nil {
            keyIDs = append(keyIDs, field.Bytes)
         }
      }
   }

   return &PSSHData{
      KeyIDs: keyIDs,
      Data:   cencHeader,
   }, nil
}
