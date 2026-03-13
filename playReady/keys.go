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

type ContentKey struct {
   KeyID      [16]byte
   KeyType    uint16
   CipherType uint16
   Length     uint16
   Value      []byte
   Integrity  [16]byte
   Key        [16]byte
}

// decode decodes a byte slice into a ContentKey structure.
func (c *ContentKey) decode(data []byte) {
   copied := copy(c.KeyID[:], data)
   data = data[copied:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data
}

func (c *ContentKey) decrypt(privKey *ecdsa.PrivateKey, auxKeys *auxKeys) error {
   log.Println("PlayReady cipher type", c.CipherType)
   switch c.CipherType {
   case 3:
      decrypted, err := elGamalDecrypt(c.Value, privKey)
      if err != nil {
         return err
      }
      copied := copy(c.Integrity[:], decrypted)
      decrypted = decrypted[copied:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.scalable(privKey, auxKeys)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(privKey *ecdsa.PrivateKey, aux *auxKeys) error {
   rootKeyInfo := c.Value[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.Value[144:]
   decrypted, err := elGamalDecrypt(rootKeyInfo[:128], privKey)
   if err != nil {
      return err
   }
   var (
      ci [16]byte
      ck [16]byte
   )
   for i := range 16 {
      ci[i] = decrypted[i*2]
      ck[i] = decrypted[i*2+1]
   }
   magicConstantZero, err := c.magicConstantZero()
   if err != nil {
      return err
   }
   rgbUplinkXkey := xorKey(ck[:], magicConstantZero)
   contentKeyPrime, err := aesEcbEncrypt(rgbUplinkXkey, ck[:])
   if err != nil {
      return err
   }
   auxKeyCalc, err := aesEcbEncrypt(aux.Keys[0].Key[:], contentKeyPrime)
   if err != nil {
      return err
   }
   oSecondaryKey, err := aesEcbEncrypt(rootKey, ck[:])
   if err != nil {
      return err
   }
   rgbKey, err := aesEcbEncrypt(leafKeys, auxKeyCalc)
   if err != nil {
      return err
   }
   rgbKey, err = aesEcbEncrypt(rgbKey, oSecondaryKey)
   if err != nil {
      return err
   }
   copied := copy(c.Integrity[:], rgbKey)
   rgbKey = rgbKey[copied:]
   copy(c.Key[:], rgbKey)
   return nil
}

// magicConstantZero returns a specific hex-decoded byte slice.
func (c *ContentKey) magicConstantZero() ([]byte, error) {
   return hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
}

type EcKey [1]*ecdsa.PrivateKey

// GenerateEcKey creates a new P-256 private key and returns it.
func GenerateEcKey() (*EcKey, error) {
   priv, err := ecdsa.GenerateKey(elliptic.P256(), nil)
   if err != nil {
      return nil, err
   }
   return &EcKey{priv}, nil
}

// DecodeEcKey decodes a raw private key byte slice into a new EcKey.
func DecodeEcKey(data []byte) (*EcKey, error) {
   if len(data) != 32 {
      return nil, errors.New("invalid private key length, expected 32 bytes")
   }

   priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), data)
   if err != nil {
      return nil, err
   }
   return &EcKey{priv}, nil
}

// Private returns the private key bytes.
func (e EcKey) Private() ([]byte, error) {
   if e[0] == nil {
      return nil, errors.New("private key is nil")
   }
   ecdhKey, err := e[0].ECDH()
   if err != nil {
      return nil, err
   }
   return ecdhKey.Bytes(), nil
}

// Public returns the public key bytes.
func (e *EcKey) Public() ([]byte, error) {
   if e[0] == nil {
      return nil, errors.New("private key is nil")
   }
   ecdhKey, err := e[0].PublicKey.ECDH()
   if err != nil {
      return nil, err
   }
   pubBytes := ecdhKey.Bytes()
   if len(pubBytes) > 0 {
      // Return 64 bytes (X and Y coordinates) without the 0x04 uncompressed prefix
      return pubBytes[1:], nil
   }
   return nil, errors.New("invalid public key length")
}

type eccKey struct {
   Curve  uint16
   Length uint16
   Value  []byte
}

// Decode decodes a byte slice into an ECCKey structure.
func (e *eccKey) decode(data []byte) {
   e.Curve = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   e.Value = data
}

type keyData struct {
   keyType uint16
   length  uint16
   flags   uint32
   // ECDSA P256 public key is 64 bytes (X and Y coordinates, 32 bytes each)
   publicKey [64]byte
   // Features indicating key usage
   usage features
}

// new initializes a new key with provided data and type.
func (k *keyData) New(data []byte, Type int) {
   k.keyType = 1  // Assuming type 1 is for ECDSA keys
   k.length = 512 // Assuming key length in bits
   copy(k.publicKey[:], data)
   k.usage.New(Type)
}

// encode encodes the key structure into a byte slice.
func (k *keyData) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, k.keyType)
   data = binary.BigEndian.AppendUint16(data, k.length)
   data = binary.BigEndian.AppendUint32(data, k.flags)
   data = append(data, k.publicKey[:]...)
   return append(data, k.usage.encode()...)
}

// decode decodes a byte slice into the key structure.
func (k *keyData) decode(data []byte) int {
   k.keyType = binary.BigEndian.Uint16(data)
   offset := 2
   k.length = binary.BigEndian.Uint16(data[offset:])
   offset += 2
   k.flags = binary.BigEndian.Uint32(data[offset:])
   offset += 4
   offset += copy(k.publicKey[:], data[offset:])
   offset += k.usage.decode(data[offset:])
   return offset
}

type keyInfo struct {
   entries uint32
   keys    []keyData
}

// new initializes a new keyInfo with signing and encryption keys.
func (k *keyInfo) New(signingKey, encryptKey []byte) {
   k.entries = 2
   k.keys = make([]keyData, 2)
   k.keys[0].New(signingKey, 1) // Type 1 for signing key
   k.keys[1].New(encryptKey, 2) // Type 2 for encryption key
}

// encode encodes the keyInfo structure into a byte slice.
func (k *keyInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, k.entries)
   for _, key := range k.keys {
      data = append(data, key.encode()...)
   }
   return data
}

// decode decodes a byte slice into the keyInfo structure.
func (k *keyInfo) decode(data []byte) {
   k.entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   k.keys = make([]keyData, k.entries)
   for i := range k.entries {
      var key keyData
      offset := key.decode(data)
      k.keys[i] = key
      data = data[offset:]
   }
}

type xmlKey struct {
   PublicKey *ecdsa.PublicKey
   X         [32]byte
}

func (x *xmlKey) New() error {
   privBytes := make([]byte, 32)
   privBytes[31] = 1

   privECDH, err := ecdh.P256().NewPrivateKey(privBytes)
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
