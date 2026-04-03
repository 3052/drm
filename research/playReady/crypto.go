// crypto.go
package playReady

import (
   "crypto/aes"
   "crypto/ecdh"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/hex"

   "41.neocities.org/diana/research/playReady/xml"
   "filippo.io/nistec"
   "github.com/emmansun/gmsm/cipher"
)

func newLa(pubKey *ecdsa.PublicKey, cipherData, kid []byte, contentId string) (*xml.La, error) {
   genKey, err := elGamalKeyGeneration()
   if err != nil {
      return nil, err
   }
   cipherValue, err := elGamalEncrypt(pubKey, genKey)
   if err != nil {
      return nil, err
   }

   headerData := xml.WrmHeaderData{
      Kid: kid,
      ProtectInfo: xml.ProtectInfo{
         AlgId:  "AESCTR",
         KeyLen: 16,
      },
   }
   if contentId != "" {
      headerData.CustomAttributes = &xml.CustomAttributes{
         ContentId: contentId,
      }
   }
   return &xml.La{
      ContentHeader: xml.ContentHeader{
         WrmHeader: xml.WrmHeader{
            Data:    headerData,
            Version: "4.0.0.0",
            XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader",
         },
      },
      EncryptedData: xml.EncryptedData{
         CipherData: xml.CipherData{
            CipherValue: cipherData,
         },
         EncryptionMethod: xml.EncryptionMethod{
            Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
         },
         KeyInfo: xml.EncryptedDataInfo{
            EncryptedKey: xml.EncryptedKey{
               CipherData: xml.CipherData{
                  CipherValue: cipherValue,
               },
               EncryptionMethod: xml.EncryptionMethod{
                  Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
               },
               KeyInfo: xml.EncryptedKeyInfo{
                  KeyName: "WMRMServer",
                  XmlNs:   "http://www.w3.org/2000/09/xmldsig#",
               },
               XmlNs: "http://www.w3.org/2001/04/xmlenc#",
            },
            XmlNs: "http://www.w3.org/2000/09/xmldsig#",
         },
         Type:  "http://www.w3.org/2001/04/xmlenc#Element",
         XmlNs: "http://www.w3.org/2001/04/xmlenc#",
      },
      Id:           "SignedData",
      LicenseNonce: make([]byte, 16),
      Version:      "1",
      XmlNs:        "http://schemas.microsoft.com/DRM/2007/03/protocols",
   }, nil
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
   return ecdsa.GenerateKey(elliptic.P256(), nil)
}

func ParseRawPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
   return ecdsa.ParseRawPrivateKey(elliptic.P256(), data)
}

func PrivateKeyBytes(key *ecdsa.PrivateKey) ([]byte, error) {
   ecdhKey, err := key.ECDH()
   if err != nil {
      return nil, err
   }
   return ecdhKey.Bytes(), nil
}

func publicKeyBytes(key *ecdsa.PrivateKey) ([]byte, error) {
   ecdhKey, err := key.PublicKey.ECDH()
   if err != nil {
      return nil, err
   }
   // Return 64 bytes (X and Y coordinates) without the 0x04 uncompressed prefix
   return ecdhKey.Bytes()[1:], nil
}

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"
const magicConstantZero = "7ee9ed4af773224f00b8ea7efb027cbb"

type xmlKey struct {
   PublicKey *ecdsa.PublicKey
   X         [32]byte
}

func (x *xmlKey) initialize() error {
   privBytes := [32]byte{1}

   privECDH, err := ecdh.P256().NewPrivateKey(privBytes[:])
   if err != nil {
      return err
   }
   pubBytes := privECDH.PublicKey().Bytes()
   x.PublicKey, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubBytes)
   if err != nil {
      return err
   }

   copy(x.X[:], pubBytes[1:33])
   return nil
}

func (x *xmlKey) aesIv() []byte {
   return x.X[:16]
}

func (x *xmlKey) aesKey() []byte {
   return x.X[16:]
}

func elGamalDecrypt(ciphertext []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
   c1Bytes := [65]byte{4}
   copy(c1Bytes[1:], ciphertext[:64])
   c1, err := nistec.NewP256Point().SetBytes(c1Bytes[:])
   if err != nil {
      return nil, err
   }

   c2Bytes := [65]byte{4}
   copy(c2Bytes[1:], ciphertext[64:128])
   c2, err := nistec.NewP256Point().SetBytes(c2Bytes[:])
   if err != nil {
      return nil, err
   }

   ecdhKey, err := privKey.ECDH()
   if err != nil {
      return nil, err
   }

   sharedSec, err := nistec.NewP256Point().ScalarMult(c1, ecdhKey.Bytes())
   if err != nil {
      return nil, err
   }

   invSec := nistec.NewP256Point().Negate(sharedSec)
   mPoint := nistec.NewP256Point().Add(c2, invSec)
   return mPoint.Bytes()[1:], nil
}

func aesEcbEncrypt(data, key []byte) ([]byte, error) {
   block, err := aes.NewCipher(key)
   if err != nil {
      return nil, err
   }
   encData := make([]byte, len(data))
   cipher.NewECBEncrypter(block).CryptBlocks(encData, data)
   return encData, nil
}

func xorKey(left, right []byte) []byte {
   if len(left) != len(right) {
      panic("slices have different lengths")
   }
   result := make([]byte, len(left))
   for i := 0; i < len(left); i++ {
      result[i] = left[i] ^ right[i]
   }
   return result
}

func elGamalEncrypt(data, pubKey *ecdsa.PublicKey) ([]byte, error) {
   randY := [32]byte{1}

   c1, err := nistec.NewP256Point().ScalarBaseMult(randY[:])
   if err != nil {
      return nil, err
   }

   keyECDH, err := pubKey.ECDH()
   if err != nil {
      return nil, err
   }

   keyPoint, err := nistec.NewP256Point().SetBytes(keyECDH.Bytes())
   if err != nil {
      return nil, err
   }

   sharedSec, err := nistec.NewP256Point().ScalarMult(keyPoint, randY[:])
   if err != nil {
      return nil, err
   }

   dataECDH, err := data.ECDH()
   if err != nil {
      return nil, err
   }

   dataPoint, err := nistec.NewP256Point().SetBytes(dataECDH.Bytes())
   if err != nil {
      return nil, err
   }

   c2 := nistec.NewP256Point().Add(dataPoint, sharedSec)

   return append(c1.Bytes()[1:], c2.Bytes()[1:]...), nil
}

func elGamalKeyGeneration() (*ecdsa.PublicKey, error) {
   uncompressed := [65]byte{4}
   _, err := hex.Decode(uncompressed[1:], []byte(wmrmPublicKey))
   if err != nil {
      return nil, err
   }

   return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed[:])
}
