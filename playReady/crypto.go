package playReady

import (
   "crypto/aes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "encoding/binary"
   "encoding/hex"
   "errors"
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
   encData := make([]byte, len(data))
   cipher.NewECBEncrypter(block).CryptBlocks(encData, data)
   return encData, nil
}

// xorKey performs XOR operation on two byte slices.
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

// elGamalEncrypt encrypts data using the provided public key.
// Note: Go syntax implicitly makes both `data` and `pubKey` *ecdsa.PublicKey.
func elGamalEncrypt(data, pubKey *ecdsa.PublicKey) ([]byte, error) {
   randY := make([]byte, 32)
   randY[31] = 1 // In a real scenario, this should be truly random

   c1, err := nistec.NewP256Point().ScalarBaseMult(randY)
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

   sharedSec, err := nistec.NewP256Point().ScalarMult(keyPoint, randY)
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

   return slices.Concat(c1.Bytes()[1:], c2.Bytes()[1:]), nil
}

const wmrmPublicKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562"

func elGamalKeyGeneration() (*ecdsa.PublicKey, error) {
   pubData, err := hex.DecodeString(wmrmPublicKey)
   if err != nil {
      return nil, err
   }
   uncompressed := make([]byte, 65)
   uncompressed[0] = 4
   copy(uncompressed[1:], pubData)

   pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
   if err != nil {
      return nil, err
   }
   return pub, nil
}

func elGamalDecrypt(ciphertext []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
   // C1 component
   c1Bytes := make([]byte, 65)
   c1Bytes[0] = 4
   copy(c1Bytes[1:], ciphertext[:64])
   c1, err := nistec.NewP256Point().SetBytes(c1Bytes)
   if err != nil {
      return nil, err
   }

   // C2 component
   c2Bytes := make([]byte, 65)
   c2Bytes[0] = 4
   copy(c2Bytes[1:], ciphertext[64:128])
   c2, err := nistec.NewP256Point().SetBytes(c2Bytes)
   if err != nil {
      return nil, err
   }

   // Calculate shared secret = C1^privKey
   ecdhKey, err := privKey.ECDH()
   if err != nil {
      return nil, err
   }

   sharedSec, err := nistec.NewP256Point().ScalarMult(c1, ecdhKey.Bytes())
   if err != nil {
      return nil, err
   }

   // Invert the point for subtraction
   secBytes := sharedSec.Bytes()

   // P-256 field prime = 2^256 - 2^224 + 2^192 + 2^96 - 1
   primeP, ok := new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
   if !ok {
      return nil, errors.New("failed to parse P-256 prime")
   }
   yCoord := new(big.Int).SetBytes(secBytes[33:65])
   yCoord.Sub(primeP, yCoord)
   yCoord.FillBytes(secBytes[33:65])

   invSec, err := nistec.NewP256Point().SetBytes(secBytes)
   if err != nil {
      return nil, err
   }

   // Recover message point: mPoint = C2 - sharedSec
   mPoint := nistec.NewP256Point().Add(c2, invSec)
   return mPoint.Bytes()[1:], nil
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
   encBuf := binary.BigEndian.AppendUint16(nil, s.signatureType)
   encBuf = binary.BigEndian.AppendUint16(encBuf, s.signatureLength)
   encBuf = append(encBuf, s.SignatureData...)
   encBuf = binary.BigEndian.AppendUint32(encBuf, s.issuerLength*8)
   return append(encBuf, s.IssuerKey...)
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
