package playReady

import (
   "41.neocities.org/drm/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "fmt"
   "github.com/emmansun/gmsm/cbcmac"
   "github.com/emmansun/gmsm/padding"
   "math/big"
)

// License represents a PlayReady license.
type License struct {
   Magic      [4]byte           // 0
   Offset     uint16            // 1
   Version    uint16            // 2
   RightsId   [16]byte          // 3
   ContentKey *ContentKey       // 4.9.10
   EccKey     *EccKey           // 4.9.42
   AuxKeys    *AuxKeys          // 4.9.81
   Signature  *LicenseSignature // 4.11
}

// decode parses a raw license byte slice into the License struct.
func (l *License) decode(data []byte) error {
   l.Magic = [4]byte(data)
   data = data[4:]
   l.Offset = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Version = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.RightsId = [16]byte(data)
   data = data[16:]
   var value1 Ftlv
   _, err := value1.decode(data) // Type 1
   if err != nil {
      return err
   }
   for len(value1.Value) >= 1 {
      var value2 Ftlv
      n, err := value2.decode(value1.Value)
      if err != nil {
         return err
      }
      value1.Value = value1.Value[n:]
      switch xmrType(value2.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         for len(value2.Value) >= 1 {
            var value3 Ftlv
            n, err = value3.decode(value2.Value)
            if err != nil {
               return err
            }
            value2.Value = value2.Value[n:]
            switch xmrType(value3.Type) {
            case contentKeyEntryType: // 10
               l.ContentKey = &ContentKey{}
               l.ContentKey.decode(value3.Value)
            case deviceKeyEntryType: // 42
               l.EccKey = &EccKey{}
               l.EccKey.decode(value3.Value)
            case auxKeyEntryType: // 81
               l.AuxKeys = &AuxKeys{}
               l.AuxKeys.decode(value3.Value)
            default:
               return fmt.Errorf("unknown key material entry type: %d", value3.Type)
            }
         }
      case signatureEntryType: // 11
         l.Signature = &LicenseSignature{}
         l.Signature.decode(value2.Value)
      default:
         return fmt.Errorf("unknown license container entry type: %d", value2.Type)
      }
   }
   return nil
}

// Decrypt processes a license response, decrypts the content key, and verifies the license.
func (l *License) Decrypt(data []byte, privK *big.Int) (*CoordX, error) {
   var envelope xml.EnvelopeResponse
   err := envelope.Unmarshal(data)
   if err != nil {
      return nil, err
   }
   data = envelope.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License
   err = l.decode(data)
   if err != nil {
      return nil, err
   }
   pubK, err := p256().dsa().PubK(privK)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(
      l.EccKey.Value, append(pubK.X.Bytes(), pubK.Y.Bytes()...),
   ) {
      return nil, errors.New("license response is not for this device")
   }
   coord, err := l.ContentKey.decrypt(privK, l.AuxKeys)
   if err != nil {
      return nil, err
   }
   err = l.verify(data, coord)
   if err != nil {
      return nil, err
   }
   return coord, nil
}

// verify checks the integrity of the license data using the decrypted content key.
func (l *License) verify(data []byte, coord *CoordX) error {
   signature := new(Ftlv).size() + l.Signature.size()
   data = data[:len(data)-signature]
   block, err := aes.NewCipher(coord.integrity())
   if err != nil {
      return err
   }
   data = cbcmac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.Signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

// RequestBody generates the XML SOAP body for a license acquisition request.
func (c *Chain) RequestBody(kid []byte, privK *big.Int) ([]byte, error) {
   cipherData, err := c.cipherData()
   if err != nil {
      return nil, err
   }
   la, err := newLa(cipherData, kid)
   if err != nil {
      return nil, err
   }
   laData, err := la.Marshal()
   if err != nil {
      return nil, err
   }
   laDigest := sha256.Sum256(laData)

   // REVERTED to original, working SignedInfo creation.
   signedInfo := xml.SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: xml.Reference{
         Uri:         "#SignedData",
         DigestValue: laDigest[:],
      },
   }

   signedData, err := signedInfo.Marshal()
   if err != nil {
      return nil, err
   }
   hashVal := sha256.Sum256(signedData)
   signature, err := sign(hashVal[:], privK)
   if err != nil {
      return nil, err
   }
   envelope := xml.Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: xml.Body{
         AcquireLicense: &xml.AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: xml.Challenge{
               Challenge: xml.InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    la,
                  Signature: xml.Signature{
                     SignedInfo:     signedInfo,
                     SignatureValue: signature,
                  },
               },
            },
         },
      },
   }
   return envelope.Marshal()
}

// cipherData encrypts the certificate chain data for the license request.
func (c *Chain) cipherData() ([]byte, error) {
   var coord CoordX
   coord.New(p256().G.X)
   block, err := aes.NewCipher(coord.Key())
   if err != nil {
      return nil, err
   }
   xmlData := xml.Data{
      CertificateChains: xml.CertificateChains{
         CertificateChain: c.Encode(),
      },
      Features: xml.Features{
         Feature: xml.Feature{"AESCBC"}, // SCALABLE
      },
   }
   data, err := xmlData.Marshal()
   if err != nil {
      return nil, err
   }
   data = padding.NewPKCS7Padding(aes.BlockSize).Pad(data)
   cipher.NewCBCEncrypter(block, coord.iv()).CryptBlocks(data, data)
   return append(coord.iv(), data...), nil
}

// newLa creates a new LA (License Acquisition) XML structure.
func newLa(cipherData, kid []byte) (*xml.La, error) {
   data, err := elGamalEncrypt(&p256().G, wmrmPublicKey())
   if err != nil {
      return nil, err
   }
   la := xml.La{
      XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/protocols",
      Id:      "SignedData",
      Version: "1",
      ContentHeader: xml.ContentHeader{
         WrmHeader: xml.WrmHeader{
            XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader",
            Version: "4.0.0.0",
            Data: xml.WrmHeaderData{
               ProtectInfo: xml.ProtectInfo{
                  KeyLen: "16",
                  AlgId:  "AESCTR",
               },
               Kid: kid, // FIXME field can be a slice
            },
         },
      },
      EncryptedData: xml.EncryptedData{
         XmlNs: "http://www.w3.org/2001/04/xmlenc#",
         Type:  "http://www.w3.org/2001/04/xmlenc#Element",
         EncryptionMethod: xml.Algorithm{
            Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
         },
         KeyInfo: xml.KeyInfo{
            XmlNs: "http://www.w3.org/2000/09/xmldsig#",
            EncryptedKey: xml.EncryptedKey{
               XmlNs: "http://www.w3.org/2001/04/xmlenc#",
               EncryptionMethod: xml.Algorithm{
                  Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
               },
               KeyInfo: xml.EncryptedKeyInfo{
                  XmlNs:   "http://www.w3.org/2000/09/xmldsig#",
                  KeyName: "WMRMServer",
               },
               CipherData: xml.CipherData{
                  CipherValue: data,
               },
            },
         },
         CipherData: xml.CipherData{
            CipherValue: cipherData,
         },
      },
   }
   return &la, nil
}
