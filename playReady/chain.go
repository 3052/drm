package playReady

import (
   "41.neocities.org/drm/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "github.com/arnaucube/cryptofun/ecc"
   "github.com/arnaucube/cryptofun/ecdsa"
   "github.com/arnaucube/cryptofun/elgamal"
   "github.com/emmansun/gmsm/cbcmac"
   "github.com/emmansun/gmsm/padding"
   "math/big"
   "slices"
)

func (c *Chain) RequestBody(kid []byte, privK *big.Int) ([]byte, error) {
   cipherData, err := c.cipherData()
   if err != nil {
      return nil, err
   }
   la, err := newLa(cipherData, kid)
   if err != nil {
      return nil, err
   }
   laData, err := la.Marshal()
   if err != nil {
      return nil, err
   }
   laDigest := sha256.Sum256(laData)
   signedInfo := xml.SignedInfo{
      XmlNs: "http://www.w3.org/2000/09/xmldsig#",
      Reference: xml.Reference{
         Uri:         "#SignedData",
         DigestValue: laDigest[:],
      },
   }
   signedData, err := signedInfo.Marshal()
   if err != nil {
      return nil, err
   }
   hashVal := sha256.Sum256(signedData)
   signature, err := sign(hashVal[:], privK)
   if err != nil {
      return nil, err
   }
   envelope := xml.Envelope{
      Soap: "http://schemas.xmlsoap.org/soap/envelope/",
      Body: xml.Body{
         AcquireLicense: &xml.AcquireLicense{
            XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols",
            Challenge: xml.Challenge{
               Challenge: xml.InnerChallenge{
                  XmlNs: "http://schemas.microsoft.com/DRM/2007/03/protocols/messages",
                  La:    la,
                  Signature: xml.Signature{
                     SignedInfo:     signedInfo,
                     SignatureValue: signature,
                  },
               },
            },
         },
      },
   }
   return envelope.Marshal()
}

func newLa(cipherData, kid []byte) (*xml.La, error) {
   data, err := elGamalEncrypt(&p256().G, wmrmPublicKey())
   if err != nil {
      return nil, err
   }
   la := xml.La{
      XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/protocols",
      Id:      "SignedData",
      Version: "1",
      ContentHeader: xml.ContentHeader{
         WrmHeader: xml.WrmHeader{
            XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader",
            Version: "4.0.0.0",
            Data: xml.WrmHeaderData{
               ProtectInfo: xml.ProtectInfo{
                  KeyLen: "16",
                  AlgId:  "AESCTR",
               },
               Kid: kid, // FIXME field can be a slice
            },
         },
      },
      EncryptedData: xml.EncryptedData{
         XmlNs: "http://www.w3.org/2001/04/xmlenc#",
         Type:  "http://www.w3.org/2001/04/xmlenc#Element",
         EncryptionMethod: xml.Algorithm{
            Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
         },
         KeyInfo: xml.KeyInfo{
            XmlNs: "http://www.w3.org/2000/09/xmldsig#",
            EncryptedKey: xml.EncryptedKey{
               XmlNs: "http://www.w3.org/2001/04/xmlenc#",
               EncryptionMethod: xml.Algorithm{
                  Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
               },
               KeyInfo: xml.EncryptedKeyInfo{
                  XmlNs:   "http://www.w3.org/2000/09/xmldsig#",
                  KeyName: "WMRMServer",
               },
               CipherData: xml.CipherData{
                  CipherValue: data,
               },
            },
         },
         CipherData: xml.CipherData{
            CipherValue: cipherData,
         },
      },
   }
   return &la, nil
}

func (c *Chain) cipherData() ([]byte, error) {
   var coord CoordX
   coord.New(p256().G.X)
   block, err := aes.NewCipher(coord.Key())
   if err != nil {
      return nil, err
   }
   xmlData := xml.Data{
      CertificateChains: xml.CertificateChains{
         CertificateChain: c.Encode(),
      },
      Features: xml.Features{
         Feature: xml.Feature{"AESCBC"}, // SCALABLE
      },
   }
   data, err := xmlData.Marshal()
   if err != nil {
      return nil, err
   }
   data = padding.NewPKCS7Padding(aes.BlockSize).Pad(data)
   cipher.NewCBCEncrypter(block, coord.iv()).CryptBlocks(data, data)
   return append(coord.iv(), data...), nil
}

type Chain struct {
   Magic        [4]byte
   Version      uint32
   Length       uint32
   Flags        uint32
   CertCount    uint32
   Certificates []Certificate
}

// Decode decodes a byte slice into the Chain structure.
func (c *Chain) Decode(data []byte) error {
   c.Magic = [4]byte(data)
   if string(c.Magic[:]) != "CHAI" {
      return errors.New("failed to find chain magic")
   }
   data = data[4:]
   c.Version = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Length = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.CertCount = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Certificates = make([]Certificate, c.CertCount)
   for i := range c.CertCount {
      var cert Certificate
      n, err := cert.decode(data)
      if err != nil {
         return err
      }
      c.Certificates[i] = cert
      data = data[n:]
   }
   return nil
}

func (c *Chain) Encode() []byte {
   data := c.Magic[:]
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.CertCount)
   for _, cert := range c.Certificates {
      data = cert.Append(data)
   }
   return data
}

func (c *Chain) verify() (bool, error) {
   modelBase := c.Certificates[c.CertCount-1].Signature.IssuerKey
   for i := len(c.Certificates) - 1; i >= 0; i-- {
      ok, err := c.Certificates[i].verify(modelBase[:])
      if err != nil {
         return false, err
      }
      if !ok {
         return false, nil
      }
      modelBase = c.Certificates[i].KeyInfo.Keys[0].PublicKey[:]
   }
   return true, nil
}

// they downgrade certs from the cert digest (hash of the signing key)
func (c *Chain) Leaf(modelPriv, encryptSignPriv *big.Int) error {
   dsa := p256().dsa()
   modelPub, err := dsa.PubK(modelPriv)
   if err != nil {
      return err
   }
   if !bytes.Equal(
      c.Certificates[0].KeyInfo.Keys[0].PublicKey[:],
      append(modelPub.X.Bytes(), modelPub.Y.Bytes()...),
   ) {
      return errors.New("zgpriv not for cert")
   }
   ok, err := c.verify()
   if err != nil {
      return err
   }
   if !ok {
      return errors.New("cert is not valid")
   }
   var cert Certificate
   copy(cert.Magic[:], "CERT")
   cert.Version = 1 // required
   {
      // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
      var features CertFeatures
      features.New(0xD)
      cert.Features = features.ftlv(0, 5)
   }
   encryptSignPub, err := dsa.PubK(encryptSignPriv)
   if err != nil {
      return err
   }
   {
      sum := sha256.Sum256(
         append(encryptSignPub.X.Bytes(), encryptSignPub.Y.Bytes()...),
      )
      cert.Info = &CertificateInfo{}
      cert.Info.New(c.Certificates[0].Info.SecurityLevel, sum[:])
   }
   cert.KeyInfo = &KeyInfo{}
   cert.KeyInfo.New(
      append(encryptSignPub.X.Bytes(), encryptSignPub.Y.Bytes()...),
   )
   {
      cert.LengthToSignature, cert.Length = cert.size()
      hashVal := sha256.Sum256(cert.Append(nil))
      signature, err := sign(hashVal[:], modelPriv)
      if err != nil {
         return err
      }
      cert.Signature = &CertSignature{}
      err = cert.Signature.New(
         signature, append(modelPub.X.Bytes(), modelPub.Y.Bytes()...),
      )
      if err != nil {
         return err
      }
   }
   c.CertCount += 1
   c.Certificates = slices.Insert(c.Certificates, 0, cert)
   c.Length += cert.Length
   return nil
}

func (c *CoordX) iv() []byte {
   return c[:16]
}

func (c *CoordX) integrity() []byte {
   return c[:16]
}

func (c *CoordX) Key() []byte {
   return c[16:]
}

func (c *CoordX) New(x *big.Int) {
   x.FillBytes(c[:])
}

type CoordX [32]byte

func (l *License) Decrypt(data []byte, privK *big.Int) (*CoordX, error) {
   var envelope xml.EnvelopeResponse
   err := envelope.Unmarshal(data)
   if err != nil {
      return nil, err
   }
   data = envelope.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License
   err = l.decode(data)
   if err != nil {
      return nil, err
   }
   pubK, err := p256().dsa().PubK(privK)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(
      l.EccKey.Value, append(pubK.X.Bytes(), pubK.Y.Bytes()...),
   ) {
      return nil, errors.New("license response is not for this device")
   }
   coord, err := l.ContentKey.decrypt(privK, l.AuxKeys)
   if err != nil {
      return nil, err
   }
   err = l.verify(data, coord)
   if err != nil {
      return nil, err
   }
   return coord, nil
}

func (c *curve) dsa() *ecdsa.DSA {
   return (*ecdsa.DSA)(c)
}

func (c *curve) eg() *elgamal.EG {
   return (*elgamal.EG)(c)
}

func sign(hashVal []byte, privK *big.Int) ([]byte, error) {
   rs, err := p256().dsa().Sign(
      new(big.Int).SetBytes(hashVal), privK, big.NewInt(1),
   )
   if err != nil {
      return nil, err
   }
   return append(rs[0].Bytes(), rs[1].Bytes()...), nil
}

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
// Starting from (RMSDK 4.7+), the new playready root public key:
// a32dff369e160df5b022106a63627412d6b174d501a3ccfa73bd441cc38ae94c
// 0f7ada348d3eb3f5dd639aa46e29e2738bf88d18267c9c7bd3b96ae5faef780b
func wmrmPublicKey() *ecc.Point {
   var p ecc.Point
   p.X, _ = new(big.Int).SetString("c8b6af16ee941aadaa5389b4af2c10e356be42af175ef3face93254e7b0b3d9b", 16)
   p.Y, _ = new(big.Int).SetString("982b27b5cb2341326e56aa857dbfd5c634ce2cf9ea74fca8f2af5957efeea562", 16)
   return &p
}

func (l *License) verify(data []byte, coord *CoordX) error {
   signature := new(Ftlv).size() + l.Signature.size()
   data = data[:len(data)-signature]
   block, err := aes.NewCipher(coord.integrity())
   if err != nil {
      return err
   }
   data = cbcmac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.Signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

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

type curve struct {
   EC ecc.EC
   G  ecc.Point
   N  *big.Int
}

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
