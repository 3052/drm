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
   Magic             [4]byte // 0:4
   Version           uint32  // 4:8
   Length            uint32  // 8:12
   LengthToSignature uint32  // 12:16
   Info              *CertificateInfo
   Security          *Ftlv
   Features          *Ftlv
   KeyInfo           *KeyInfo
   // Manufacturer provides easy access to the parsed manufacturer data.
   Manufacturer *ManufacturerData
   // manufacturerFtlv stores the original Ftlv block to ensure byte-perfect re-serialization for verification.
   manufacturerFtlv *Ftlv
   Signature        *CertSignature
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
         // Store the original Ftlv block for perfect re-serialization.
         c.manufacturerFtlv = &value
         // Also parse the data into the convenient struct for access.
         c.Manufacturer = &ManufacturerData{}
         if err := c.Manufacturer.decode(value.Value); err != nil {
            return 0, fmt.Errorf("failed to parse manufacturer object: %w", err)
         }
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
      // The flag for Info is always 1
      data = c.Info.ftlv(1, objTypeBasic).Append(data)
   }
   if c.Security != nil {
      data = c.Security.Append(data)
   }
   if c.Features != nil {
      data = c.Features.Append(data)
   }
   if c.KeyInfo != nil {
      // The flag for KeyInfo is always 1
      data = c.KeyInfo.ftlv(1, objTypeKey).Append(data)
   }

   // CRITICAL FIX: Prioritize the original ftlv for re-serialization,
   // but fall back to the public struct for newly created certificates.
   if c.manufacturerFtlv != nil {
      data = c.manufacturerFtlv.Append(data)
   } else if c.Manufacturer != nil {
      // The flag for Manufacturer is typically 0
      data = c.Manufacturer.ftlv(0, objTypeManufacturer).Append(data)
   }

   if c.Signature != nil {
      // The flag for Signature is always 0
      data = c.Signature.ftlv(0, objTypeSignature).Append(data)
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

   // CRITICAL FIX: Ensure size calculation works for both decoded and created certificates.
   if c.manufacturerFtlv != nil {
      n += c.manufacturerFtlv.size()
   } else if c.Manufacturer != nil {
      n += new(Ftlv).size()
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
