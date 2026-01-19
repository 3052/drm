package bcert

type ChainHeader struct {
	Version uint32
	CbChain uint32
	Flags   uint32
	Certs   uint32
}

type CertificateHeader struct {
	Version      uint32
	CbCert       uint32
	SignedLength uint32
	RawData      []byte
}

type CertificateChain struct {
	Header      ChainHeader
	CertHeaders []CertificateHeader
}

type Certificate struct {
	Version      uint32
	CbCert       uint32
	SignedLength uint32

	BasicInformation      *BasicInformation
	FeatureInformation    *FeatureInformation
	KeyInformation        *KeyInformation
	SignatureInformation  *SignatureInformation
	DomainInformation     *DomainInformation
	DeviceInformation     *DeviceInformation
	PCInfo                *PCInfo
	ManufacturerInfo      *ManufacturerInformation
	SilverlightInfo       *SilverlightInformation
	MeteringInfo          *MeteringInformation
	ExtDataSigKeyInfo     *ExtDataSigKeyInfo
	ExtDataContainer      *ExtDataContainer
	ServerTypeInfo        *ServerTypeInformation
	SecurityVersion       *SecurityVersion
	SecurityVersion2      *SecurityVersion
}

type BasicInformation struct {
	CertID         [16]byte
	SecurityLevel  uint32
	Type           uint32
	Flags          uint32
	DigestValue    []byte
	ExpirationDate uint32
	ClientID       [16]byte
}

type FeatureInformation struct {
	FeatureSet uint32
	Features   []uint32
}

type KeyType struct {
	Type      uint16
	KeyLength uint16
	KeyValue  []byte
	KeyUsages []uint32
}

type KeyInformation struct {
	Entries  uint32
	KeyTypes []KeyType
}

type SignatureInformation struct {
	SignatureType uint16
	Signature     []byte
	IssuerKey     []byte
}

type DomainInformation struct {
	ServiceID [16]byte
	AccountID [16]byte
	Revision  uint32
	DomainURL []byte
}

type DeviceInformation struct {
	ManufacturerKey [64]byte
}

type PCInfo struct {
	SecurityVersion uint32
}

type ManufacturerInformation struct {
	ManufacturerName []byte
	ModelName        []byte
	ModelNumber      []byte
}

type SilverlightInformation struct {
	Data []byte
}

type MeteringInformation struct {
	Data []byte
}

type ExtDataSigKeyInfo struct {
	KeyType   uint16
	KeyLength uint16
	PublicKey []byte
}

type ExtDataEntry struct {
	Type uint32
	Data []byte
}

type ExtDataContainer struct {
	Entries []ExtDataEntry
}

type ServerTypeInformation struct {
	SecurityVersion uint32
}

type SecurityVersion struct {
	MinimumSecurityLevel uint32
	MaximumSecurityLevel uint32
}
