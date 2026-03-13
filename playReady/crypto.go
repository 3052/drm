package playReady

import (
   "crypto/aes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "encoding/hex"
   "filippo.io/nistec"
   "github.com/emmansun/gmsm/cipher"
   "math/big"
   "slices"
)

func aesEcbEncrypt(data, key []byte) ([]byte, error) {
   block, err := aes.NewCipher(key)
   if err != nil {
      return nil, err
   }
   data1 := make([]byte, len(data))
   cipher.NewECBEncrypter(block).CryptBlocks(data1, data)
   return data1, nil
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

// Fill type removed as requested.

func elGamalEncrypt(data, key *ecdsa.PublicKey) []byte {
   y := make([]byte, 32)
   y[31] = 1 // In a real scenario, y should be truly random

   c1, _ := nistec.NewP256Point().ScalarBaseMult(y)

   keyECDH, _ := key.ECDH()
   keyPoint, _ := nistec.NewP256Point().SetBytes(keyECDH.Bytes())

   s, _ := nistec.NewP256Point().ScalarMult(keyPoint, y)

   dataECDH, _ := data.ECDH()
   dataPoint, _ := nistec.NewP256Point().SetBytes(dataECDH.Bytes())

   c2 := nistec.NewP256Point().Add(dataPoint, s)

   return slices.Concat(c1.Bytes()[1:], c2.Bytes()[1:])
}

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func elGamalKeyGeneration() *ecdsa.PublicKey {
   data, _ := hex.DecodeString(wmrmPublicKey)
   uncompressed := make([]byte, 65)
   uncompressed[0] = 4
   copy(uncompressed[1:], data)

   pub, _ := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
   return pub
}

func elGamalDecrypt(ciphertext []byte, x *ecdsa.PrivateKey) []byte {
   // C1 component
   c1Bytes := make([]byte, 65)
   c1Bytes[0] = 4
   copy(c1Bytes[1:], ciphertext[:64])
   c1, _ := nistec.NewP256Point().SetBytes(c1Bytes)

   // C2 component
   c2Bytes := make([]byte, 65)
   c2Bytes[0] = 4
   copy(c2Bytes[1:], ciphertext[64:128])
   c2, _ := nistec.NewP256Point().SetBytes(c2Bytes)

   // Calculate shared secret s = C1^x
   ecdhKey, _ := x.ECDH()
   s, _ := nistec.NewP256Point().ScalarMult(c1, ecdhKey.Bytes())

   // Invert the point for subtraction
   sBytes := s.Bytes()

   // P-256 field prime: P = 2^256 - 2^224 + 2^192 + 2^96 - 1
   P, _ := new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
   Y := new(big.Int).SetBytes(sBytes[33:65])
   Y.Sub(P, Y)
   Y.FillBytes(sBytes[33:65])

   invS, _ := nistec.NewP256Point().SetBytes(sBytes)

   // Recover message point: M = C2 - s
   m := nistec.NewP256Point().Add(c2, invS)
   return m.Bytes()[1:]
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
