// license.go
package playReady

import (
   "41.neocities.org/drm/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "encoding/binary"
   "errors"
   "github.com/emmansun/gmsm/cbcmac"
)

func (l *License) verify(contentIntegrity []byte) error {
   data := l.encode()

   // The MAC is calculated over the entire license EXCEPT the Signature FTLV.
   // The Signature FTLV is strictly the last object in the Outer Container.
   // FTLV header (8 bytes) + Signature header (4 bytes) + Signature Data
   sigLen := 8 + 4 + len(l.Signature.Data)
   data = data[:len(data)-sigLen]

   block, err := aes.NewCipher(contentIntegrity)
   if err != nil {
      return err
   }
   data = cbcmac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.Signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

// License represents a parsed PlayReady license.
type License struct {
   Magic    [4]byte
   Offset   uint16
   Version  uint16
   RightsID [16]byte

   ContentKey   *ContentKey
   EccKey       *eccKey
   Signature    *signature
   AuxKeyObject *auxKeys

   // Container dynamics matching the certificate pattern
   outerContainerFlags uint16
   outerOrder          []uint16
   outerUnknown        map[uint16][]byte
   outerFlags          map[uint16]uint16

   keyMaterialOrder   []uint16
   keyMaterialUnknown map[uint16][]byte
   keyMaterialFlags   map[uint16]uint16
}

func (l *License) encode() []byte {
   var keyMaterialRaw []byte
   for _, recType := range l.keyMaterialOrder {
      var valBytes []byte
      switch xmrType(recType) {
      case contentKeyEntryType:
         valBytes = l.ContentKey.encode()
      case deviceKeyEntryType:
         valBytes = l.EccKey.encode()
      case auxKeyEntryType:
         valBytes = l.AuxKeyObject.encode()
      default:
         valBytes = l.keyMaterialUnknown[recType]
      }
      flags := l.keyMaterialFlags[recType]
      f := ftlv{Flags: flags, Type: recType, Length: uint32(len(valBytes) + 8), Value: valBytes}
      keyMaterialRaw = append(keyMaterialRaw, f.encode()...)
   }

   var outerRaw []byte
   for _, recType := range l.outerOrder {
      var valBytes []byte
      switch xmrType(recType) {
      case keyMaterialContainerEntryType:
         valBytes = keyMaterialRaw
      case signatureEntryType:
         valBytes = l.Signature.encode()
      default:
         valBytes = l.outerUnknown[recType]
      }
      flags := l.outerFlags[recType]
      f := ftlv{Flags: flags, Type: recType, Length: uint32(len(valBytes) + 8), Value: valBytes}
      outerRaw = append(outerRaw, f.encode()...)
   }

   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)

   f := ftlv{Flags: l.outerContainerFlags, Type: uint16(outerContainerEntryType), Length: uint32(len(outerRaw) + 8), Value: outerRaw}
   return append(data, f.encode()...)
}

func (l *License) decode(data []byte) error {
   copied := copy(l.Magic[:], data)
   data = data[copied:]
   l.Offset = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Version = binary.BigEndian.Uint16(data)
   data = data[2:]
   copied = copy(l.RightsID[:], data)
   data = data[copied:]

   outerContainer, _ := decodeFtlv(data)
   l.outerContainerFlags = outerContainer.Flags

   l.outerOrder = nil
   l.outerUnknown = make(map[uint16][]byte)
   l.outerFlags = make(map[uint16]uint16)

   l.keyMaterialOrder = nil
   l.keyMaterialUnknown = make(map[uint16][]byte)
   l.keyMaterialFlags = make(map[uint16]uint16)

   var outerOffset int
   for outerOffset < len(outerContainer.Value) {
      outerValue, outerN := decodeFtlv(outerContainer.Value[outerOffset:])
      outerOffset += outerN

      l.outerOrder = append(l.outerOrder, outerValue.Type)
      l.outerFlags[outerValue.Type] = outerValue.Flags

      switch xmrType(outerValue.Type) {
      case keyMaterialContainerEntryType: // 9
         var innerOffset int
         for innerOffset < len(outerValue.Value) {
            innerValue, innerN := decodeFtlv(outerValue.Value[innerOffset:])
            innerOffset += innerN

            l.keyMaterialOrder = append(l.keyMaterialOrder, innerValue.Type)
            l.keyMaterialFlags[innerValue.Type] = innerValue.Flags

            switch xmrType(innerValue.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = decodeContentKey(innerValue.Value)
            case deviceKeyEntryType: // 42
               l.EccKey = decodeEccKey(innerValue.Value)
            case auxKeyEntryType: // 81
               l.AuxKeyObject = decodeAuxKeys(innerValue.Value)
            default:
               l.keyMaterialUnknown[innerValue.Type] = innerValue.Value
            }
         }
      case signatureEntryType: // 11
         l.Signature = decodeSignature(outerValue.Value)
      default:
         l.outerUnknown[outerValue.Type] = outerValue.Value
      }
   }
   return nil
}

// ParseLicense processes XML license data and returns the parsed License object.
func ParseLicense(data []byte) (*License, error) {
   l := &License{} // single letter 'l' allowed because it is the return variable
   var envelope xml.EnvelopeResponse
   err := xml.Unmarshal(data, &envelope)
   if err != nil {
      return nil, err
   }
   if envelope.Body.Fault != nil {
      return nil, errors.New(envelope.Body.Fault.Fault)
   }
   err = l.decode(envelope.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License,
   )
   if err != nil {
      return nil, err
   }
   return l, nil
}

// Decrypt validates the license for the given device key, verifies its signature,
// and returns the decrypted content key bytes.
func (l *License) Decrypt(encryptKey *ecdsa.PrivateKey) ([]byte, error) {
   pubBytes, err := publicKeyBytes(encryptKey)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(l.EccKey.Value, pubBytes) {
      return nil, errors.New("license response is not for this device")
   }

   decryptedKey, err := l.ContentKey.decrypt(encryptKey, l.AuxKeyObject)
   if err != nil {
      return nil, err
   }

   if len(decryptedKey) < 32 {
      return nil, errors.New("invalid key length")
   }

   // Verify signature using the integrity block (first 16 bytes)
   err = l.verify(decryptedKey[:16])
   if err != nil {
      return nil, err
   }

   // Return only the user content key slice directly
   return decryptedKey[16:32], nil
}
