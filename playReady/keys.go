// keys.go
package playReady

import (
   "crypto/ecdh"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/hex"
   "errors"
   "log"
)

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

const magicConstantZero = "7ee9ed4af773224f00b8ea7efb027cbb"

// decrypt returns the raw decrypted payload, acting on the ContentKey defined in drm_xmr.go.
func (c *ContentKey) decrypt(privKey *ecdsa.PrivateKey, aux *AuxKey) ([]byte, error) {
   log.Println("PlayReady cipher type", c.KeyEncryptionCipherType)
   switch c.KeyEncryptionCipherType {
   case 3:
      return elGamalDecrypt(c.EncryptedKeyBuffer, privKey)
   case 6: // scalable
      return c.scalable(privKey, aux)
   }
   return nil, errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(privKey *ecdsa.PrivateKey, aux *AuxKey) ([]byte, error) {
   if len(c.EncryptedKeyBuffer) < 144 || !aux.Valid || aux.Entries == 0 {
      return nil, errors.New("invalid scalable key data or missing aux keys")
   }

   rootKeyInfo := c.EncryptedKeyBuffer[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.EncryptedKeyBuffer[144:]

   decrypted, err := elGamalDecrypt(rootKeyInfo[:128], privKey)
   if err != nil {
      return nil, err
   }
   var (
      ci [16]byte
      ck [16]byte
   )
   for index := range 16 {
      ci[index] = decrypted[index*2]
      ck[index] = decrypted[index*2+1]
   }

   magicZero, err := hex.DecodeString(magicConstantZero)
   if err != nil {
      return nil, err
   }

   rgbUplinkXkey := xorKey(ck[:], magicZero)
   contentKeyPrime, err := aesEcbEncrypt(rgbUplinkXkey, ck[:])
   if err != nil {
      return nil, err
   }
   // Access key map updated to use the layout introduced in drm_xmr.go
   auxKeyCalc, err := aesEcbEncrypt(aux.EntriesList[0].Key[:], contentKeyPrime)
   if err != nil {
      return nil, err
   }
   oSecondaryKey, err := aesEcbEncrypt(rootKey, ck[:])
   if err != nil {
      return nil, err
   }
   rgbKey, err := aesEcbEncrypt(leafKeys, auxKeyCalc)
   if err != nil {
      return nil, err
   }
   return aesEcbEncrypt(rgbKey, oSecondaryKey)
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
