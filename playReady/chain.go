package playReady

import (
   "bytes"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "math/big"
   "slices"
)

// Chain represents a certificate chain.
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

// Encode serializes the Chain structure into a byte slice.
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

// verify validates the entire certificate chain.
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

// Leaf generates and adds a new leaf certificate to the chain.
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
