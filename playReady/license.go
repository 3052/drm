package playReady

import (
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "encoding/binary"
   "errors"
   "github.com/emmansun/gmsm/cbcmac"
)

// Verify checks the integrity of the license using the CMAC of the content integrity key.
func (l *License) Verify(contentIntegrity []byte) error {
   data := l.encode()
   data = data[:len(data)-int(l.Signature.Length)]
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
   Magic          [4]byte
   Offset         uint16
   Version        uint16
   RightsID       [16]byte
   OuterContainer ftlv
   ContentKey     *ContentKey
   EccKey         *eccKey
   Signature      *signature
   AuxKeyObject   *auxKeys
}

func (l *License) encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   return append(data, l.OuterContainer.encode()...)
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
   l.OuterContainer.decode(data)
   var outerOffset int
   for outerOffset < int(l.OuterContainer.Length)-16 {
      var outerValue ftlv
      outerOffset += outerValue.decode(l.OuterContainer.Value[outerOffset:])
      switch xmrType(outerValue.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         var innerOffset int
         for innerOffset < int(outerValue.Length)-16 {
            var innerValue ftlv
            innerOffset += innerValue.decode(outerValue.Value[innerOffset:])
            switch xmrType(innerValue.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = &ContentKey{}
               l.ContentKey.decode(innerValue.Value)
            case deviceKeyEntryType: // 42
               l.EccKey = &eccKey{}
               l.EccKey.decode(innerValue.Value)
            case auxKeyEntryType: // 81
               l.AuxKeyObject = &auxKeys{}
               l.AuxKeyObject.decode(innerValue.Value)
            default:
               return errors.New("FTLV.type")
            }
         }
      case signatureEntryType: // 11
         l.Signature = &signature{}
         l.Signature.decode(outerValue.Value)
         l.Signature.Length = uint16(outerValue.Length)
      default:
         return errors.New("FTLV.type")
      }
   }
   return nil
}

// DecryptLicense processes license data using the provided ECDSA private key and returns the parsed License.
func DecryptLicense(privKey *ecdsa.PrivateKey, data []byte) (*License, error) {
   l := &License{} // single letter 'l' allowed because it is the return variable
   var envelope EnvelopeResponse
   err := envelope.Unmarshal(data)
   if err != nil {
      return nil, err
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
   pubBytes, err := PublicKeyBytes(privKey)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(l.EccKey.Value, pubBytes) {
      return nil, errors.New("license response is not for this device")
   }
   err = l.ContentKey.decrypt(privKey, l.AuxKeyObject)
   if err != nil {
      return nil, err
   }
   err = l.Verify(l.ContentKey.Integrity[:])
   if err != nil {
      return nil, err
   }
   return l, nil
}
