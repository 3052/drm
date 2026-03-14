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

   l.OuterContainer, _ = decodeFtlv(data)

   var outerOffset int
   for outerOffset < int(l.OuterContainer.Length)-16 {
      outerValue, outerN := decodeFtlv(l.OuterContainer.Value[outerOffset:])
      outerOffset += outerN

      switch xmrType(outerValue.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         var innerOffset int
         for innerOffset < int(outerValue.Length)-16 {
            innerValue, innerN := decodeFtlv(outerValue.Value[innerOffset:])
            innerOffset += innerN

            switch xmrType(innerValue.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = decodeContentKey(innerValue.Value)
            case deviceKeyEntryType: // 42
               l.EccKey = decodeEccKey(innerValue.Value)
            case auxKeyEntryType: // 81
               l.AuxKeyObject = decodeAuxKeys(innerValue.Value)
            default:
               return errors.New("FTLV.type")
            }
         }
      case signatureEntryType: // 11
         l.Signature = decodeSignature(outerValue.Value)
         l.Signature.Length = uint16(outerValue.Length)
      default:
         return errors.New("FTLV.type")
      }
   }
   return nil
}

// DecryptLicense processes license data using the provided ECDSA private key and returns the parsed License.
func DecryptLicense(encryptKey *ecdsa.PrivateKey, data []byte) (*License, error) {
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
   pubBytes, err := publicKeyBytes(encryptKey)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(l.EccKey.Value, pubBytes) {
      return nil, errors.New("license response is not for this device")
   }
   err = l.ContentKey.decrypt(encryptKey, l.AuxKeyObject)
   if err != nil {
      return nil, err
   }
   err = l.verify(l.ContentKey.Integrity[:])
   if err != nil {
      return nil, err
   }
   return l, nil
}
