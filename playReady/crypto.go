package playReady

import (
   "github.com/arnaucube/cryptofun/ecc"
   "github.com/arnaucube/cryptofun/ecdsa"
   "github.com/arnaucube/cryptofun/elgamal"
   "math/big"
   "slices"
)

// curve defines the parameters for an elliptic curve.
type curve struct {
   EC ecc.EC
   G  ecc.Point
   N  *big.Int
}

func (c *curve) dsa() *ecdsa.DSA {
   return (*ecdsa.DSA)(c)
}

func (c *curve) eg() *elgamal.EG {
   return (*elgamal.EG)(c)
}

// p256 returns the parameters for the NIST P-256 curve.
// nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
func p256() *curve {
   var c curve
   c.EC.A = big.NewInt(-3)
   c.EC.Q, _ = new(big.Int).SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
   c.G.X, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
   c.G.Y, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
   c.N, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
   return &c
}

// wmrmPublicKey returns the WMRM server's public key for license requests.
// Starting from (RMSDK 4.7+), the new playready root public key:
// a32dff369e160df5b022106a63627412d6b174d501a3ccfa73bd441cc38ae94c
// 0f7ada348d3eb3f5dd639aa46e29e2738bf88d18267c9c7bd3b96ae5faef780b
func wmrmPublicKey() *ecc.Point {
   var p ecc.Point
   p.X, _ = new(big.Int).SetString("c8b6af16ee941aadaa5389b4af2c10e356be42af175ef3face93254e7b0b3d9b", 16)
   p.Y, _ = new(big.Int).SetString("982b27b5cb2341326e56aa857dbfd5c634ce2cf9ea74fca8f2af5957efeea562", 16)
   return &p
}

// sign creates an ECDSA signature for a given hash.
func sign(hashVal []byte, privK *big.Int) ([]byte, error) {
   rs, err := p256().dsa().Sign(
      new(big.Int).SetBytes(hashVal), privK, big.NewInt(1),
   )
   if err != nil {
      return nil, err
   }
   return append(rs[0].Bytes(), rs[1].Bytes()...), nil
}

// elGamalEncrypt performs ElGamal encryption on an elliptic curve point.
func elGamalEncrypt(m, pubK *ecc.Point) ([]byte, error) {
   c, err := p256().eg().Encrypt(*m, *pubK, big.NewInt(1))
   if err != nil {
      return nil, err
   }
   data := slices.Concat(
      c[0].X.Bytes(), c[0].Y.Bytes(), c[1].X.Bytes(), c[1].Y.Bytes(),
   )
   return data, nil
}

// elGamalDecrypt performs ElGamal decryption.
func elGamalDecrypt(data []byte, privK *big.Int) ([]byte, error) {
   // Unmarshal C1 component
   c1 := ecc.Point{
      X: new(big.Int).SetBytes(data[:32]),
      Y: new(big.Int).SetBytes(data[32:64]),
   }
   // Unmarshal C2 component
   c2 := ecc.Point{
      X: new(big.Int).SetBytes(data[64:96]),
      Y: new(big.Int).SetBytes(data[96:]),
   }
   point, err := p256().eg().Decrypt([2]ecc.Point{c1, c2}, privK)
   if err != nil {
      return nil, err
   }
   return append(point.X.Bytes(), point.Y.Bytes()...), nil
}
