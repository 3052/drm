package playReady

import (
   "bytes"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "fmt"
   "github.com/arnaucube/cryptofun/ecc"
   "math/big"
)

// Certificate represents a PlayReady certificate structure.
type Certificate struct {
   Magic             [4]byte          // 0:4
   Version           uint32           // 4:8
   Length            uint32           // 8:12
   LengthToSignature uint32           // 12:16
   Info              *CertificateInfo // 0x1
   Security          *Ftlv            // 0x11
   Features          *Ftlv            // 0x5
   KeyInfo           *KeyInfo         // 0x6
   Manufacturer      *Ftlv            // 0x7
   Signature         *CertSignature   // 0x8
}

// Constants for object types within the certificate structure.
const (
   objTypeBasic            = 0x0001
   objTypeDomain           = 0x0002
   objTypePc               = 0x0003
   objTypeDevice           = 0x0004
   objTypeFeature          = 0x0005
   objTypeKey              = 0x0006
   objTypeManufacturer     = 0x0007
   objTypeSignature        = 0x0008
   objTypeSilverlight      = 0x0009
   objTypeMetering         = 0x000A
   objTypeExtDataSignKey   = 0x000B
   objTypeExtDataContainer = 0x000C
   objTypeExtDataSignature = 0x000D
   objTypeExtDataHwid      = 0x000E
   objTypeServer           = 0x000F
   objTypeSecurityVersion  = 0x0010
   objTypeSecurityVersion2 = 0x0011
)

// decode parses a byte slice to populate the Certificate structure.
func (c *Certificate) decode(data []byte) (int, error) {
   n := copy(c.Magic[:], data)
   if string(c.Magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }
   c.Version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.Length = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.LengthToSignature = binary.BigEndian.Uint32(data[n:])
   n += 4
   for n < int(c.Length) {
      var value Ftlv
      bytesReadFromFtlv, err := value.decode(data[n:])
      if err != nil {
         return 0, err
      }
      switch value.Type {
      case objTypeBasic: // 0x0001
         c.Info = &CertificateInfo{}
         c.Info.decode(value.Value)
      case objTypeSecurityVersion2: // 0x0011
         c.Security = &value
      case objTypeFeature: // 0x0005
         c.Features = &value
      case objTypeKey: // 0x0006
         c.KeyInfo = &KeyInfo{}
         c.KeyInfo.decode(value.Value)
      case objTypeManufacturer: // 0x0007
         c.Manufacturer = &value
      case objTypeSignature: // 0x0008
         c.Signature = &CertSignature{}
         err := c.Signature.decode(value.Value)
         if err != nil {
            return 0, err
         }
      default:
         return 0, fmt.Errorf("unknown certificate object type: 0x%X", value.Type)
      }
      n += bytesReadFromFtlv
   }
   return n, nil // Return total bytes consumed and nil for no error
}

// Append serializes the Certificate structure into a byte slice.
func (c *Certificate) Append(data []byte) []byte {
   data = append(data, c.Magic[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Version)
   data = binary.BigEndian.AppendUint32(data, c.Length)
   data = binary.BigEndian.AppendUint32(data, c.LengthToSignature)
   if c.Info != nil {
      data = c.Info.ftlv(1, 1).Append(data)
   }
   if c.Security != nil {
      data = c.Security.Append(data)
   }
   if c.Features != nil {
      data = c.Features.Append(data)
   }
   if c.KeyInfo != nil {
      data = c.KeyInfo.ftlv(1, 6).Append(data)
   }
   if c.Manufacturer != nil {
      data = c.Manufacturer.Append(data)
   }
   if c.Signature != nil {
      data = c.Signature.ftlv(0, 8).Append(data)
   }
   return data
}

// size calculates the serialized size of the certificate.
func (c *Certificate) size() (uint32, uint32) {
   n := len(c.Magic)
   n += 4 // Version
   n += 4 // Length
   n += 4 // LengthToSignature
   if c.Info != nil {
      n += new(Ftlv).size()
      n += binary.Size(c.Info)
   }
   if c.Security != nil {
      n += c.Security.size()
   }
   if c.Features != nil {
      n += c.Features.size()
   }
   if c.KeyInfo != nil {
      n += new(Ftlv).size()
      n += c.KeyInfo.size()
   }
   if c.Manufacturer != nil {
      n += c.Manufacturer.size()
   }
   n1 := n
   n1 += new(Ftlv).size()
   n1 += c.Signature.size()
   return uint32(n), uint32(n1)
}

// verify checks the certificate's signature against a given public key.
func (c *Certificate) verify(pubK []byte) (bool, error) {
   if !bytes.Equal(c.Signature.IssuerKey, pubK) {
      return false, nil
   }
   hashVal := func() *big.Int {
      data := c.Append(nil)
      data = data[:c.LengthToSignature]
      sum := sha256.Sum256(data)
      return new(big.Int).SetBytes(sum[:])
   }()
   sign := c.Signature.Signature
   return p256().dsa().Verify(
      hashVal,
      [2]*big.Int{
         new(big.Int).SetBytes(sign[:32]),
         new(big.Int).SetBytes(sign[32:]),
      },
      ecc.Point{
         X: new(big.Int).SetBytes(pubK[:32]),
         Y: new(big.Int).SetBytes(pubK[32:]),
      },
   )
}
