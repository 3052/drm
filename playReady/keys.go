// keys.go
package playReady

import (
   "crypto/ecdh"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "log"
)

type EccKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

func (e *EccKey) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, e.Curve)
   data = binary.BigEndian.AppendUint16(data, e.Length)
   return append(data, e.Value...)
}

// decodeEccKey decodes a byte slice into an ECCKey structure.
func decodeEccKey(data []byte) *EccKey {
   e := &EccKey{}
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Value = data
   return e
}

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

type ContentKey struct {
   KeyID      [16]byte
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
}

func (c *ContentKey) encode() []byte {
   data := append([]byte(nil), c.KeyID[:]...)
   data = binary.BigEndian.AppendUint16(data, c.KeyType)
   data = binary.BigEndian.AppendUint16(data, c.CipherType)
   data = binary.BigEndian.AppendUint16(data, c.Length)
   return append(data, c.Value...)
}

// decodeContentKey decodes a byte slice into a new ContentKey structure.
func decodeContentKey(data []byte) *ContentKey {
   c := &ContentKey{}
   copied := copy(c.KeyID[:], data)
   data = data[copied:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data
   return c
}

// decrypt returns the raw decrypted payload.
func (c *ContentKey) decrypt(privKey *ecdsa.PrivateKey, auxKeys *AuxKeys) ([]byte, error) {
   log.Println("PlayReady cipher type", c.CipherType)
   switch c.CipherType {
   case 3:
      return elGamalDecrypt(c.Value, privKey)
   case 6:
      return c.scalable(privKey, auxKeys)
   }
   return nil, errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(privKey *ecdsa.PrivateKey, aux *AuxKeys) ([]byte, error) {
   rootKeyInfo := c.Value[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.Value[144:]
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
