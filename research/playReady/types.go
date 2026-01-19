package bcert

type GUID [16]byte
type ID [16]byte

type KeyType struct {
   Type      uint16
   KeyLength uint16
   Flags     uint32
   KeyValue  []byte
   KeyUsages []uint32
   UsageSet  uint32
}

type ExtendedHeader struct {
   Version      uint32
   Length       uint32
   SignedLength uint32
}

type ChainExtendedHeader struct {
   Version uint32
   CbChain uint32
   Flags   uint32
   Certs   uint32
}

type BasicInfo struct {
   CertID         GUID
   SecurityLevel  uint32
   Flags          uint32
   Type           uint32
   DigestValue    []byte
   ExpirationDate uint32
   ClientID       GUID
}

type DomainInfo struct {
   ServiceID GUID
   AccountID GUID
   Revision  uint32
   DomainURL []byte
}

type PCInfo struct {
   SecurityVersion uint32
}

type DeviceInfo struct {
   MaxLicenseSize       uint32
   MaxHeaderSize        uint32
   MaxLicenseChainDepth uint32
}

type SilverlightInfo struct {
   SecurityVersion uint32
   PlatformID      uint32
}

type ServerTypeInfo struct {
   WarningStartDate uint32
}

type MeteringInfo struct {
   MeteringID  GUID
   MeteringURL []byte
}

type SecurityVersion struct {
   SecurityVersion uint32
   PlatformID      uint32
}

type FeatureInfo struct {
   Features   []uint32
   FeatureSet uint32
}

type KeyInfo struct {
   Entries  uint32
   KeyTypes []KeyType
}

type ManufacturerInfo struct {
   Flags            uint32
   ManufacturerName []byte
   ModelName        []byte
   ModelNumber      []byte
}

type ExDataSigKeyInfo struct {
   Type     uint16
   KeyLen   uint16
   Flags    uint32
   KeyValue []byte
}

type SignatureInfo struct {
   SignatureType uint16
   Signature     []byte
   IssuerKey     []byte
}

type HWID struct {
   Data []byte
}

type ExtDataSigInfo struct {
   SignatureType uint16
   Signature     []byte
}

type ExtendedDataContainer struct {
   HwidRecord                 *HWID
   ExDataSignatureInformation *ExtDataSigInfo
   RawData                    []byte
}

type Certificate struct {
   HeaderData              ExtendedHeader
   BasicInformation        *BasicInfo
   DomainInformation       *DomainInfo
   PCInfo                  *PCInfo
   DeviceInformation       *DeviceInfo
   SilverlightInformation  *SilverlightInfo
   ServerTypeInformation   *ServerTypeInfo
   MeteringInformation     *MeteringInfo
   SecurityVersion         *SecurityVersion
   SecurityVersion2        *SecurityVersion
   FeatureInformation      *FeatureInfo
   KeyInformation          *KeyInfo
   ManufacturerInformation *ManufacturerInfo
   ExDataSigKeyInfo        *ExDataSigKeyInfo
   SignatureInformation    *SignatureInfo
   ExDataContainer         *ExtendedDataContainer
   RawData                 []byte
}

type CertHeader struct {
   HeaderData ExtendedHeader
   Offset     uint32
   Index      uint32
   RawData    []byte
}

type CertificateChain struct {
   Header          ChainExtendedHeader
   CertHeaders     []CertHeader
   SecurityVersion uint32
   PlatformID      uint32
   Expiration      uint32
   RawData         []byte
}
