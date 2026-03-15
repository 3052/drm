// models_cert.go
package playReady

import (
   "encoding/hex"
   "strings"
)

// Object Types
const (
   ObjTypeBasic            = 0x0001
   ObjTypeDomain           = 0x0002
   ObjTypePc               = 0x0003
   ObjTypeDevice           = 0x0004
   ObjTypeFeature          = 0x0005
   ObjTypeKey              = 0x0006
   ObjTypeManufacturer     = 0x0007
   ObjTypeSignature        = 0x0008
   ObjTypeSilverlight      = 0x0009
   ObjTypeMetering         = 0x000a
   ObjTypeExtDataSignKey   = 0x000b
   ObjTypeExtDataContainer = 0x000c
   ObjTypeExtDataSignature = 0x000d
   ObjTypeExtDataHwid      = 0x000e
   ObjTypeServer           = 0x000f
   ObjTypeSecurityVersion  = 0x0010
   ObjTypeSecurityVersion2 = 0x0011
)

const (
   CertHeaderTag = 0x43455254 // "CERT"
   CertVersion   = 0x00000001
)

const (
   ChainHeaderTag = 0x43484149 // "CHAI"
   ChainVersion   = 0x00000001
)

type ObjectHeader struct {
   Flags    uint16
   Type     uint16
   CbLength uint32
}

type CertHeader struct {
   HeaderTag           uint32 // = CertHeaderTag
   Version             uint32 // = CertVersion
   CbCertificate       uint32
   CbCertificateSigned uint32
}

type CertId struct {
   Rgb [16]byte
}

func (c CertId) String() string {
   return hex.EncodeToString(c.Rgb[:])
}

type ClientId struct {
   Rgb [16]byte
}

func (c ClientId) String() string {
   return hex.EncodeToString(c.Rgb[:])
}

type BasicInfo struct {
   Header         ObjectHeader
   CertificateID  CertId
   SecurityLevel  uint32
   Flags          uint32
   Type           uint32
   DigestValue    [32]byte
   ExpirationDate uint32
   ClientID       ClientId
}

type DeviceInfo struct {
   Header        ObjectHeader
   CbMaxLicense  uint32
   CbMaxHeader   uint32
   MaxChainDepth uint32
}

type FeatureInfo struct {
   Header            ObjectHeader
   NumFeatureEntries uint32
   FeatureSet        []uint32
}

type CertKey struct {
   Type     uint16
   Length   uint16
   Flags    uint32
   Value    []byte
   UsageSet []uint32
}

type KeyInfo struct {
   Header  ObjectHeader
   NumKeys uint32
   Keys    []CertKey
}

type PaddedString string

func (ps PaddedString) String() string {
   return strings.TrimRight(string(ps), "\x00")
}

type ManufacturerStrings struct {
   ManufacturerName PaddedString
   ModelName        PaddedString
   ModelNumber      PaddedString
}

type ManufacturerInfo struct {
   Header              ObjectHeader
   Flags               uint32
   ManufacturerStrings ManufacturerStrings
}

type SignatureData struct {
   Cb    uint16
   Value []byte
}

type SignatureInfo struct {
   Header          ObjectHeader
   SignatureType   uint16
   SignatureData   SignatureData
   IssuerKeyLength uint32 // bits natively
   IssuerKey       []byte
}

type Certificate struct {
   Header           CertHeader
   BasicInfo        *BasicInfo
   DeviceInfo       *DeviceInfo
   FeatureInfo      *FeatureInfo
   KeyInfo          *KeyInfo
   ManufacturerInfo *ManufacturerInfo
   SignatureInfo    *SignatureInfo

   RecordOrder    []uint16
   UnknownRecords map[uint16][]byte
}

type ChainHeader struct {
   HeaderTag uint32 // = ChainHeaderTag
   Version   uint32 // = ChainVersion
   CbChain   uint32
   Flags     uint32
   Certs     uint32
}

type Chain struct {
   Header       ChainHeader
   Certificates []Certificate
}
