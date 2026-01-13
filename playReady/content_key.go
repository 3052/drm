package playReady

import (
   "crypto/aes"
   "encoding/hex"
   "errors"
   "github.com/emmansun/gmsm/cipher"
   "math/big"
)

// decrypt chooses the correct decryption method based on the CipherType.
func (c *ContentKey) decrypt(privK *big.Int, aux *AuxKeys) (*CoordX, error) {
   switch c.CipherType {
   case 3:
      decrypt, err := elGamalDecrypt(c.Value, privK)
      if err != nil {
         return nil, err
      }
      return (*CoordX)(decrypt), nil
   case 6:
      return c.scalable(privK, aux)
   }
   return nil, errors.New("cannot decrypt key")
}

// scalable handles the decryption of a scalable content key.
func (c *ContentKey) scalable(privK *big.Int, aux *AuxKeys) (*CoordX, error) {
   rootKeyInfo, leafKeys := c.Value[:144], c.Value[144:]
   rootKey := rootKeyInfo[128:]
   decrypted, err := elGamalDecrypt(rootKeyInfo[:128], privK)
   if err != nil {
      return nil, err
   }
   var (
      ci [16]byte
      ck [16]byte
   )
   for i := range 16 {
      ci[i] = decrypted[i*2]
      ck[i] = decrypted[i*2+1]
   }
   magicConstantZero, err := hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
   if err != nil {
      return nil, err
   }
   rgbUplinkXkey := xorKey(magicConstantZero, ck[:])
   contentKeyPrime, err := aesEcbEncrypt(rgbUplinkXkey, ck[:])
   if err != nil {
      return nil, err
   }
   auxKeyCalc, err := aesEcbEncrypt(aux.Keys[0].Key[:], contentKeyPrime)
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
   rgbKey, err = aesEcbEncrypt(rgbKey, oSecondaryKey)
   if err != nil {
      return nil, err
   }
   return (*CoordX)(rgbKey), nil
}

// aesEcbEncrypt provides AES encryption in ECB mode.
func aesEcbEncrypt(data, key []byte) ([]byte, error) {
   block, err := aes.NewCipher(key)
   if err != nil {
      return nil, err
   }
   data1 := make([]byte, len(data))
   cipher.NewECBEncrypter(block).CryptBlocks(data1, data)
   return data1, nil
}
