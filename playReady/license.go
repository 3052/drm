package playReady

import (
   "bytes"
   "crypto/aes"
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
   var n1 int
   for n1 < int(l.OuterContainer.Length)-16 {
      var value ftlv
      n1 += value.decode(l.OuterContainer.Value[n1:])
      switch xmrType(value.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         var n2 int
         for n2 < int(value.Length)-16 {
            var value1 ftlv
            n2 += value1.decode(value.Value[n2:])
            switch xmrType(value1.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = &ContentKey{}
               l.ContentKey.decode(value1.Value)
            case deviceKeyEntryType: // 42
               l.EccKey = &eccKey{}
               l.EccKey.decode(value1.Value)
            case auxKeyEntryType: // 81
               l.AuxKeyObject = &auxKeys{}
               l.AuxKeyObject.decode(value1.Value)
            default:
               return errors.New("FTLV.type")
            }
         }
      case signatureEntryType: // 11
         l.Signature = &signature{}
         l.Signature.decode(value.Value)
         l.Signature.Length = uint16(value.Length)
      default:
         return errors.New("FTLV.type")
      }
   }
   return nil
}

// DecryptLicense processes license data using the provided EcKey and returns the parsed License.
func (e *EcKey) DecryptLicense(data []byte) (*License, error) {
   licenseObj := &License{}
   var envelope EnvelopeResponse
   err := envelope.Unmarshal(data)
   if err != nil {
      return nil, err
   }
   err = licenseObj.decode(envelope.
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
   pubBytes, err := e.Public()
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(licenseObj.EccKey.Value, pubBytes) {
      return nil, errors.New("license response is not for this device")
   }
   err = licenseObj.ContentKey.decrypt(e[0], licenseObj.AuxKeyObject)
   if err != nil {
      return nil, err
   }
   err = licenseObj.Verify(licenseObj.ContentKey.Integrity[:])
   if err != nil {
      return nil, err
   }
   return licenseObj, nil
}
