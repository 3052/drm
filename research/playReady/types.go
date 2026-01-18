package playready

// Chain represents a full certificate chain ('CHAI').
type Chain struct {
   Header       *ChainExtendedHeader
   Certificates []*Cert
   RawData      []byte `json:"-"` // Preserves original byte slice for perfect round-trip
}

// Cert represents a single binary certificate ('CERT'). It now has explicit fields
// for all known object types, making the structure concrete.
type Cert struct {
   Header                  *ExtendedHeader
   BasicInformation        *BasicInfo
   DomainInformation       *DomainInfo
   PCInfo                  *PCInfo
   DeviceInfo              *DeviceInfo
   SilverlightInformation  *SilverlightInfo
   ServerTypeInformation   *ServerTypeInfo
   MeteringInformation     *MeteringInfo
   SecurityVersion         *SecurityVersion
   SecurityVersion2        *SecurityVersion2
   FeatureInformation      *FeatureInfo
   KeyInformation          *KeyInfo
   ManufacturerInformation *ManufacturerInfo
   ExDataSigKeyInfo        *ExDataSigKeyInfo
   SignatureInformation    *SignatureInfo
   ExDataContainer         *ExtendedDataContainer
   UnknownObjects          []*UnknownObject
   RawData                 []byte `json:"-"`
}

// ChainExtendedHeader corresponds to DRM_BCERTFORMAT_CHAIN_EXTENDED_HEADER.
type ChainExtendedHeader struct {
   Version uint32
   Length  uint32
   Flags   uint32
   Certs   uint32
}

// ExtendedHeader corresponds to DRM_BCERTFORMAT_EXTENDED_HEADER.
type ExtendedHeader struct {
   Version      uint32
   Length       uint32
   SignedLength uint32
}

// BasicInfo corresponds to DRM_BCERTFORMAT_BASIC_INFO.
type BasicInfo struct {
   CertID         [16]byte
   SecurityLevel  uint32
   Flags          uint32
   Type           uint32
   DigestValue    []byte
   ExpirationDate uint32
   ClientID       [16]byte
}

// DomainInfo corresponds to DRM_BCERTFORMAT_DOMAIN_INFO.
type DomainInfo struct {
   ServiceID [16]byte
   AccountID [16]byte
   Revision  uint32
   DomainURL []byte
}

// PCInfo corresponds to DRM_BCERTFORMAT_PC_INFO.
type PCInfo struct {
   SecurityVersion uint32
}

// DeviceInfo corresponds to DRM_BCERTFORMAT_DEVICE_INFO.
type DeviceInfo struct {
   MaxLicenseSize       uint32
   MaxHeaderSize        uint32
   MaxLicenseChainDepth uint32
}

// SilverlightInfo corresponds to DRM_BCERTFORMAT_SILVERLIGHT_INFO.
type SilverlightInfo struct {
   SecurityVersion uint32
   PlatformID      uint32
}

// ServerTypeInfo corresponds to DRM_BCERTFORMAT_SERVER_TYPE_INFO.
type ServerTypeInfo struct {
   WarningStartDate uint32
}

// MeteringInfo corresponds to DRM_BCERTFORMAT_METERING_INFO.
type MeteringInfo struct {
   MeteringID  [16]byte
   MeteringURL []byte
}

// SecurityVersion corresponds to DRM_BCERTFORMAT_SECURITY_VERSION.
type SecurityVersion struct {
   SecurityVersion uint32
   PlatformID      uint32
}

// SecurityVersion2 corresponds to DRM_BCERTFORMAT_SECURITY_VERSION2.
type SecurityVersion2 struct {
   SecurityVersion uint32
   PlatformID      uint32
}

// FeatureInfo corresponds to DRM_BCERTFORMAT_FEATURE_INFO.
type FeatureInfo struct {
   Features   []uint32
   FeatureSet uint32 // Runtime computed value
}

// KeyInfo corresponds to DRM_BCERTFORMAT_KEY_INFO.
type KeyInfo struct {
   Keys []KeyType
}

// KeyType corresponds to DRM_BCERTFORMAT_KEY_TYPE.
type KeyType struct {
   Type      uint16
   KeyLength uint16
   Flags     uint32
   KeyValue  []byte
   KeyUsages []uint32
   UsageSet  uint32 // Runtime computed value
}

// ManufacturerInfo corresponds to DRM_BCERTFORMAT_MANUFACTURER_INFO.
type ManufacturerInfo struct {
   Flags            uint32
   ManufacturerName []byte
   ModelName        []byte
   ModelNumber      []byte
}

// ExDataSigKeyInfo corresponds to DRM_BCERTFORMAT_EX_DATA_SIGKEY_INFO.
type ExDataSigKeyInfo struct {
   Type     uint16
   KeyLen   uint16
   Flags    uint32
   KeyValue []byte
}

// SignatureInfo corresponds to DRM_BCERTFORMAT_SIGNATURE_INFO.
type SignatureInfo struct {
   SignatureType uint16
   Signature     []byte
   IssuerKey     []byte
}

// HWID corresponds to DRM_BCERTFORMAT_HWID.
type HWID struct {
   Data []byte
}

// ExtDataSigInfo corresponds to DRM_BCERTFORMAT_EXT_DATA_SIG_INFO.
type ExtDataSigInfo struct {
   SignatureType uint16
   Signature     []byte
}

// ExtendedDataContainer corresponds to DRM_BCERTFORMAT_EXTENDED_DATA_CONTAINER.
type ExtendedDataContainer struct {
   HwidRecord                 *HWID
   ExDataSignatureInformation *ExtDataSigInfo
   ExtendedData               []*UnknownObject
}

// UnknownObject is used to store objects that are not explicitly defined.
type UnknownObject struct {
   ObjectType  uint16
   ObjectFlags uint16
   Data        []byte
}
