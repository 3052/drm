package playReady

import (
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "encoding/hex"
   "github.com/deatil/go-cryptobin/cryptobin/crypto"
   "math/big"
   "slices"
)

// aesECBHandler performs AES ECB encryption/decryption.
func aesECBHandler(data, key []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).
         Aes().ECB().NoPadding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

// aesCBCHandler performs AES CBC encryption/decryption with PKCS7 padding.
func aesCBCHandler(data, key, iv []byte, encrypt bool) ([]byte, error) {
   if encrypt {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Encrypt()
      return bin.ToBytes(), bin.Error()
   } else {
      bin := crypto.FromBytes(data).WithKey(key).WithIv(iv).
         Aes().CBC().PKCS7Padding().Decrypt()
      return bin.ToBytes(), bin.Error()
   }
}

// xorKey performs XOR operation on two byte slices.
func xorKey(a, b []byte) []byte {
   if len(a) != len(b) {
      panic("slices have different lengths")
   }
   c := make([]byte, len(a))
   for i := 0; i < len(a); i++ {
      c[i] = a[i] ^ b[i]
   }
   return c
}

type Fill byte

func (f Fill) Read(data []byte) (int, error) {
   for index := range data {
      data[index] = byte(f)
   }
   return len(data), nil
}

// they downgrade certs from the cert digest (hash of the signing key)
func (f Fill) key() (*EcKey, error) {
   key, err := ecdsa.GenerateKey(elliptic.P256(), f)
   if err != nil {
      return nil, err
   }
   return &EcKey{key}, nil
}

func elGamalEncrypt(data, key *ecdsa.PublicKey) []byte {
   g := elliptic.P256()
   y := big.NewInt(1) // In a real scenario, y should be truly random
   c1x, c1y := g.ScalarBaseMult(y.Bytes())
   sX, sY := g.ScalarMult(key.X, key.Y, y.Bytes())
   c2X, c2Y := g.Add(data.X, data.Y, sX, sY)
   return slices.Concat(c1x.Bytes(), c1y.Bytes(), c2X.Bytes(), c2Y.Bytes())
}

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func elGamalKeyGeneration() *ecdsa.PublicKey {
   data, _ := hex.DecodeString(wmrmPublicKey)
   var key ecdsa.PublicKey
   key.X = new(big.Int).SetBytes(data[:32])
   key.Y = new(big.Int).SetBytes(data[32:])
   return &key
}

func elGamalDecrypt(ciphertext []byte, x *ecdsa.PrivateKey) []byte {
   // generator
   g := elliptic.P256()
   // Unmarshal C1 component
   c1X := new(big.Int).SetBytes(ciphertext[:32])
   c1Y := new(big.Int).SetBytes(ciphertext[32:64])
   // Unmarshal C2 component
   c2X := new(big.Int).SetBytes(ciphertext[64:96])
   c2Y := new(big.Int).SetBytes(ciphertext[96:])
   // Calculate shared secret s = C1^x
   sX, sY := g.ScalarMult(c1X, c1Y, x.D.Bytes())
   // Invert the point for subtraction
   sY.Neg(sY)
   sY.Mod(sY, g.Params().P)
   // Recover message point: M = C2 - s
   mX, mY := g.Add(c2X, c2Y, sX, sY)
   return append(mX.Bytes(), mY.Bytes()...)
}

type ecdsaSignature struct {
   signatureType   uint16
   signatureLength uint16
   SignatureData   []byte // The actual signature bytes
   issuerLength    uint32
   IssuerKey       []byte // The public key of the issuer that signed this
}

func (s *ecdsaSignature) New(signatureData, signingKey []byte) {
   s.signatureType = 1
   s.signatureLength = uint16(len(signatureData))
   s.SignatureData = signatureData
   s.issuerLength = uint32(len(signingKey))
   s.IssuerKey = signingKey
}

func (s *ecdsaSignature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, s.signatureType)
   data = binary.BigEndian.AppendUint16(data, s.signatureLength)
   data = append(data, s.SignatureData...)
   data = binary.BigEndian.AppendUint32(data, s.issuerLength*8)
   return append(data, s.IssuerKey...)
}

func (s *ecdsaSignature) decode(data []byte) {
   s.signatureType = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.signatureLength = binary.BigEndian.Uint16(data)
   data = data[2:]
   s.SignatureData = data[:s.signatureLength]
   data = data[s.signatureLength:]
   s.issuerLength = binary.BigEndian.Uint32(data)
   data = data[4:]
   s.IssuerKey = data
}
