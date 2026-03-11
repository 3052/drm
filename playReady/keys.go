package playReady

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "math/big"
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
   n := copy(c.KeyID[:], data)
   data = data[n:]
   c.KeyType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.CipherType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Length = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.Value = data
}

func (c *ContentKey) decrypt(key *ecdsa.PrivateKey, auxKeys *auxKeys) error {
   switch c.CipherType {
   case 3:
      decrypted := elGamalDecrypt(c.Value, key)
      n := copy(c.Integrity[:], decrypted)
      decrypted = decrypted[n:]
      copy(c.Key[:], decrypted)
      return nil
   case 6:
      return c.scalable(key, auxKeys)
   }
   return errors.New("cannot decrypt key")
}

func (c *ContentKey) scalable(key *ecdsa.PrivateKey, auxKeys *auxKeys) error {
   rootKeyInfo := c.Value[:144]
   rootKey := rootKeyInfo[128:]
   leafKeys := c.Value[144:]
   decrypted := elGamalDecrypt(rootKeyInfo[:128], key)
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
   contentKeyPrime, err := aesECBHandler(rgbUplinkXkey, ck[:], true)
   if err != nil {
      return err
   }
   auxKeyCalc, err := aesECBHandler(auxKeys.Keys[0].Key[:], contentKeyPrime, true)
   if err != nil {
      return err
   }
   oSecondaryKey, err := aesECBHandler(rootKey, ck[:], true)
   if err != nil {
      return err
   }
   rgbKey, err := aesECBHandler(leafKeys, auxKeyCalc, true)
   if err != nil {
      return err
   }
   rgbKey, err = aesECBHandler(rgbKey, oSecondaryKey, true)
   if err != nil {
      return err
   }
   n := copy(c.Integrity[:], rgbKey)
   rgbKey = rgbKey[n:]
   copy(c.Key[:], rgbKey)
   return nil
}

// magicConstantZero returns a specific hex-decoded byte slice.
func (*ContentKey) magicConstantZero() ([]byte, error) {
   return hex.DecodeString("7ee9ed4af773224f00b8ea7efb027cbb")
}

type EcKey [1]*ecdsa.PrivateKey

// Private returns the private key bytes.
func (e EcKey) Private() []byte {
   return e[0].D.Bytes()
}

// PublicBytes returns the public key bytes.
func (e *EcKey) Public() []byte {
   return append(e[0].PublicKey.X.Bytes(), e[0].PublicKey.Y.Bytes()...)
}

func (e *EcKey) decode(data []byte) {
   var public ecdsa.PublicKey
   public.Curve = elliptic.P256()
   public.X, public.Y = public.Curve.ScalarBaseMult(data)
   var private ecdsa.PrivateKey
   private.D = new(big.Int).SetBytes(data)
   private.PublicKey = public
   e[0] = &private
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
   n := 2
   k.length = binary.BigEndian.Uint16(data[n:])
   n += 2
   k.flags = binary.BigEndian.Uint32(data[n:])
   n += 4
   n += copy(k.publicKey[:], data[n:])
   n += k.usage.decode(data[n:])
   return n
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
      n := key.decode(data)
      k.keys[i] = key
      data = data[n:]
   }
}

type xmlKey struct {
   PublicKey ecdsa.PublicKey
   X         [32]byte
}

func (x *xmlKey) New() {
   x.PublicKey.X, x.PublicKey.Y = elliptic.P256().ScalarBaseMult([]byte{1})
   x.PublicKey.X.FillBytes(x.X[:])
}

func (x *xmlKey) aesIv() []byte {
   return x.X[:16]
}

func (x *xmlKey) aesKey() []byte {
   return x.X[16:]
}
