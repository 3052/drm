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

type KeyData struct {
   KeyType uint16
   Length  uint16
   Flags   uint32
   // ECDSA P256 public key is 64 bytes (X and Y coordinates, 32 bytes each)
   PublicKey [64]byte
   // Features indicating key usage
   Usage Features
}

// initialize initializes a new key with provided data and type.
func (k *KeyData) initialize(data []byte, Type int) {
   k.KeyType = 1  // Assuming type 1 is for ECDSA keys
   k.Length = 512 // Assuming key length in bits
   copy(k.PublicKey[:], data)
   k.Usage.initialize(Type)
}

// encode encodes the key structure into a byte slice.
func (k *KeyData) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, k.KeyType)
   data = binary.BigEndian.AppendUint16(data, k.Length)
   data = binary.BigEndian.AppendUint32(data, k.Flags)
   data = append(data, k.PublicKey[:]...)
   return append(data, k.Usage.encode()...)
}

// decodeKeyData decodes a byte slice into a KeyData structure.
func decodeKeyData(data []byte) (KeyData, int) {
   k := KeyData{}
   k.KeyType = binary.BigEndian.Uint16(data)
   n := 2 // single letter 'n' allowed because it is the return variable
   k.Length = binary.BigEndian.Uint16(data[n:])
   n += 2
   k.Flags = binary.BigEndian.Uint32(data[n:])
   n += 4
   n += copy(k.PublicKey[:], data[n:])
   feat, featN := decodeFeatures(data[n:])
   k.Usage = *feat
   n += featN
   return k, n
}

type KeyInfo struct {
   Entries uint32
   Keys    []KeyData
}

// initialize initializes a new KeyInfo with signing and encryption keys.
func (k *KeyInfo) initialize(signingKey, encryptKey []byte) {
   k.Entries = 2
   k.Keys = make([]KeyData, 2)
   k.Keys[0].initialize(signingKey, 1) // Type 1 for signing key
   k.Keys[1].initialize(encryptKey, 2) // Type 2 for encryption key
}

// encode encodes the KeyInfo structure into a byte slice.
func (k *KeyInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, k.Entries)
   for _, key := range k.Keys {
      data = append(data, key.encode()...)
   }
   return data
}

// decodeKeyInfo decodes a byte slice into a new KeyInfo structure.
func decodeKeyInfo(data []byte) *KeyInfo {
   k := &KeyInfo{}
   k.Entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   k.Keys = make([]KeyData, k.Entries)
   for index := range k.Entries {
      key, offset := decodeKeyData(data)
      k.Keys[index] = key
      data = data[offset:]
   }
   return k
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
