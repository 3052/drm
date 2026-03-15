// drm_xmr.go
package playReady

const (
   HeaderLength       = (4 * 2) + 16 // Assuming SIZEOF(DRM_ID) == 16
   BaseObjectLength   = (2 * 2) + 4
   MaximumObjectDepth = 5

   MagicConstant = 0x584D5200 // 'XMR\0'
   Unlimited     = 0xFFFFFFFF // MAX_UNSIGNED_TYPE( DRM_DWORD )

   RightsCopyFromV1 = 19
   MaxCopyCount     = 249
   SourceIDMaxCount = 100
)

type Version uint16

const (
   VersionInvalid Version = 0x0000
   Version1       Version = 0x0001
   Version2       Version = 0x0002
   Version3       Version = 0x0003
   VersionMax     Version = Version3
)

type ObjectFlags uint16

const (
   FlagsNone               ObjectFlags = 0x0000
   FlagsMustUnderstand     ObjectFlags = 0x0001
   FlagsContainer          ObjectFlags = 0x0002
   FlagsAllowExternalParse ObjectFlags = 0x0004
   FlagsBestEffort         ObjectFlags = 0x0008
   FlagsHasSecureState     ObjectFlags = 0x0010
)

type SettingsFlags uint16

const (
   SettingsFlagCannotPersist SettingsFlags = 0x0001
)

type SymmetricEncryptionType uint16

const (
   SymmetricEncryptionTypeInvalid   SymmetricEncryptionType = 0x0000
   SymmetricEncryptionTypeAes128Ctr SymmetricEncryptionType = 0x0001
   SymmetricEncryptionTypeRc4Cipher SymmetricEncryptionType = 0x0002
   SymmetricEncryptionTypeAes128Ecb SymmetricEncryptionType = 0x0003
   SymmetricEncryptionTypeCocktail  SymmetricEncryptionType = 0x0004
)

type AsymmetricEncryptionType uint16

const (
   AsymmetricEncryptionTypeInvalid        AsymmetricEncryptionType = 0x0000
   AsymmetricEncryptionTypeRsa1024        AsymmetricEncryptionType = 0x0001
   AsymmetricEncryptionTypeChainedLicense AsymmetricEncryptionType = 0x0002
   AsymmetricEncryptionTypeEcc256         AsymmetricEncryptionType = 0x0003
   AsymmetricEncryptionTypeEcc256WithKz   AsymmetricEncryptionType = 0x0004
)

type SymmetricKeyEncryptionType uint16

const (
   SymmetricKeyEncryptionTypeInvalid      SymmetricKeyEncryptionType = 0x0000
   SymmetricKeyEncryptionTypeAes128Ecb    SymmetricKeyEncryptionType = 0x0001
   SymmetricKeyEncryptionTypeAes128EcbSlk SymmetricKeyEncryptionType = 0x0002
)

type EccCurveType uint16

const (
   EccCurveTypeInvalid EccCurveType = 0x0000
   EccCurveTypeP256    EccCurveType = 0x0001
)

type SignatureType uint16

const (
   SignatureTypeInvalid    SignatureType = 0x0000
   SignatureTypeAes128Omac SignatureType = 0x0001
   SignatureTypeSha256Hmac SignatureType = 0x0002
)

type GlobalRightsSettings uint16

const (
   RightsCannotPersist      GlobalRightsSettings = 0x001
   RightsAllowBackupRestore GlobalRightsSettings = 0x004
   RightsCollaborativePlay  GlobalRightsSettings = 0x008
   RightsBaseLicense        GlobalRightsSettings = 0x010
   RightsCannotBindLicense  GlobalRightsSettings = 0x040
   RightsTempStoreOnly      GlobalRightsSettings = 0x080
)

type ExtensibleRestrictionState uint16

const (
   ExtensibleRestrictionStateCount     ExtensibleRestrictionState = 0x02
   ExtensibleRestrictionStateDate      ExtensibleRestrictionState = 0x03
   ExtensibleRestrictionStateByteArray ExtensibleRestrictionState = 0x04
)

const (
   EmbeddingBehaviorInvalid uint16 = 0x00
   EmbeddingBehaviorIgnore  uint16 = 0x01
   EmbeddingBehaviorCopy    uint16 = 0x02
   EmbeddingBehaviorMove    uint16 = 0x03
)

type UplinkChecksumType uint16

const (
   UplinkChecksumTypeXmrV1    UplinkChecksumType = 0x00
   UplinkChecksumTypeAesOmac1 UplinkChecksumType = 0x01
)

type ObjectType uint16

const (
   ObjectTypeInvalid                                       ObjectType = 0x0000
   ObjectTypeOuterContainer                                ObjectType = 0x0001
   ObjectTypeGlobalPolicyContainer                         ObjectType = 0x0002
   ObjectTypeMinimumEnvironmentObject                      ObjectType = 0x0003
   ObjectTypePlaybackPolicyContainer                       ObjectType = 0x0004
   ObjectTypeOutputProtectionObject                        ObjectType = 0x0005
   ObjectTypeUplinkKidObject                               ObjectType = 0x0006
   ObjectTypeExplicitAnalogVideoOutputProtectionContainer  ObjectType = 0x0007
   ObjectTypeAnalogVideoOutputConfigurationObject          ObjectType = 0x0008
   ObjectTypeKeyMaterialContainer                          ObjectType = 0x0009
   ObjectTypeContentKeyObject                              ObjectType = 0x000A
   ObjectTypeSignatureObject                               ObjectType = 0x000B
   ObjectTypeSerialNumberObject                            ObjectType = 0x000C
   ObjectTypeSettingsObject                                ObjectType = 0x000D
   ObjectTypeCopyPolicyContainer                           ObjectType = 0x000E
   ObjectTypeAllowPlaylistburnPolicyContainer              ObjectType = 0x000F
   ObjectTypeInclusionListObject                           ObjectType = 0x0010
   ObjectTypePriorityObject                                ObjectType = 0x0011
   ObjectTypeExpirationObject                              ObjectType = 0x0012
   ObjectTypeIssuedateObject                               ObjectType = 0x0013
   ObjectTypeExpirationAfterFirstuseObject                 ObjectType = 0x0014
   ObjectTypeExpirationAfterFirststoreObject               ObjectType = 0x0015
   ObjectTypeMeteringObject                                ObjectType = 0x0016
   ObjectTypePlaycountObject                               ObjectType = 0x0017
   ObjectTypeGracePeriodObject                             ObjectType = 0x001A
   ObjectTypeCopycountObject                               ObjectType = 0x001B
   ObjectTypeCopyProtectionObject                          ObjectType = 0x001C
   ObjectTypePlaylistburnCountObject                       ObjectType = 0x001F
   ObjectTypeRevocationInformationVersionObject            ObjectType = 0x0020
   ObjectTypeRsaDeviceKeyObject                            ObjectType = 0x0021
   ObjectTypeSourceidObject                                ObjectType = 0x0022
   ObjectTypeRevocationContainer                           ObjectType = 0x0025
   ObjectTypeRsaLicenseGranterKeyObject                    ObjectType = 0x0026
   ObjectTypeUseridObject                                  ObjectType = 0x0027
   ObjectTypeRestrictedSourceidObject                      ObjectType = 0x0028
   ObjectTypeDomainIdObject                                ObjectType = 0x0029
   ObjectTypeEccDeviceKeyObject                            ObjectType = 0x002A
   ObjectTypeGenerationNumberObject                        ObjectType = 0x002B
   ObjectTypePolicyMetadataObject                          ObjectType = 0x002C
   ObjectTypeOptimizedContentKeyObject                     ObjectType = 0x002D
   ObjectTypeExplicitDigitalAudioOutputProtectionContainer ObjectType = 0x002E
   ObjectTypeRingtonePolicyContainer                       ObjectType = 0x002F
   ObjectTypeExpirationAfterFirstplayObject                ObjectType = 0x0030
   ObjectTypeDigitalAudioOutputConfigurationObject         ObjectType = 0x0031
   ObjectTypeRevocationInformationVersion2Object           ObjectType = 0x0032
   ObjectTypeEmbeddingBehaviorObject                       ObjectType = 0x0033
   ObjectTypeSecurityLevel                                 ObjectType = 0x0034
   ObjectTypeCopyToPcContainer                             ObjectType = 0x0035
   ObjectTypePlayEnablerContainer                          ObjectType = 0x0036
   ObjectTypeMoveEnablerObject                             ObjectType = 0x0037
   ObjectTypeCopyEnablerContainer                          ObjectType = 0x0038
   ObjectTypePlayEnablerObject                             ObjectType = 0x0039
   ObjectTypeCopyEnablerObject                             ObjectType = 0x003A
   ObjectTypeUplinkKid2Object                              ObjectType = 0x003B
   ObjectTypeCopyPolicy2Container                          ObjectType = 0x003C
   ObjectTypeCopycount2Object                              ObjectType = 0x003D
   ObjectTypeRingtoneEnablerObject                         ObjectType = 0x003E
   ObjectTypeExecutePolicyContainer                        ObjectType = 0x003F
   ObjectTypeExecutePolicyObject                           ObjectType = 0x0040
   ObjectTypeReadPolicyContainer                           ObjectType = 0x0041
   ObjectTypeExtensiblePolicyReserved42                    ObjectType = 0x0042
   ObjectTypeExtensiblePolicyReserved43                    ObjectType = 0x0043
   ObjectTypeExtensiblePolicyReserved44                    ObjectType = 0x0044
   ObjectTypeExtensiblePolicyReserved45                    ObjectType = 0x0045
   ObjectTypeExtensiblePolicyReserved46                    ObjectType = 0x0046
   ObjectTypeExtensiblePolicyReserved47                    ObjectType = 0x0047
   ObjectTypeExtensiblePolicyReserved48                    ObjectType = 0x0048
   ObjectTypeExtensiblePolicyReserved49                    ObjectType = 0x0049
   ObjectTypeExtensiblePolicyReserved4a                    ObjectType = 0x004A
   ObjectTypeExtensiblePolicyReserved4b                    ObjectType = 0x004B
   ObjectTypeExtensiblePolicyReserved4c                    ObjectType = 0x004C
   ObjectTypeExtensiblePolicyReserved4d                    ObjectType = 0x004D
   ObjectTypeExtensiblePolicyReserved4e                    ObjectType = 0x004E
   ObjectTypeExtensiblePolicyReserved4f                    ObjectType = 0x004F
   ObjectTypeRemovalDateObject                             ObjectType = 0x0050
   ObjectTypeAuxKeyObject                                  ObjectType = 0x0051
   ObjectTypeUplinkxObject                                 ObjectType = 0x0052
   ObjectTypeMaximumDefined                                ObjectType = 0x0052
)

type CommonInternalDefines struct {
   IsContainer bool
   Parent      uint16
   Flags       uint16
}

type Word struct {
   Valid bool
   Value uint16
}

type Dword struct {
   Valid bool
   Value uint32
}

type Guid struct {
   Valid      bool
   GuidBuffer []byte
   IGuid      uint32
}

type GuidList struct {
   Valid      bool
   GuidsCount uint32
   GuidBuffer []byte
   IGuids     uint32
}

type ByteArray struct {
   Valid      bool
   DataSize   uint32
   DataBuffer []byte
   IData      uint32
}

type Empty struct {
   Valid bool
}

type DwordVersioned struct {
   Valid   bool
   Version uint32
   Value   uint32
}

type MinimumEnvironment struct {
   Valid                              bool
   Version                            uint32
   MinimumSecurityLevel               uint16
   MinimumAppRevocationListVersion    uint32
   MinimumDeviceRevocationListVersion uint32
}

type SerialNumber = ByteArray
type Rights = Word
type RevocationInformationVersion = DwordVersioned
type Priority = Dword
type SourceID = Dword
type RestrictedSourceID = Empty
type EmbeddingBehavior = Word
type MoveEnabler = Dword

const (
   SourceIDNone         uint32 = 0
   SourceIDMacrovision  uint32 = 1
   SourceIDCgmsa        uint32 = 2
   SourceIDWss          uint32 = 3
   SourceIDDigitalCable uint32 = 4
   SourceIDAtsc         uint32 = 5
   SourceIDPdrm         uint32 = 260
   SourceIDLegacyDvr    uint32 = 261
   SourceIDV1           uint32 = 262
)

type Expiration struct {
   Valid     bool
   BeginDate uint32
   EndDate   uint32
}

type IssueDate = Dword
type GracePeriod = Dword
type Metering = Guid
type ExpirationAfterFirstUse = DwordVersioned
type ExpirationAfterFirstStore = Dword
type InclusionList = GuidList

type UnknownObject struct {
   Valid  bool
   Type   uint16
   Flags  uint16
   Buffer []byte
   IBData uint32
   CBData uint32
   Next   *UnknownObject
}

type UnknownContainer struct {
   Valid             bool
   Type              uint16
   Flags             uint16
   Object            *UnknownObject
   UnkChildContainer *UnknownContainer
   Next              *UnknownContainer
}

type GenerationNumber = Dword

type DomainID struct {
   Valid       bool
   AccountID   []byte
   IAccountID  uint32
   CBAccountID uint32
   Revision    uint32
}

type PolicyMetadataObject struct {
   Valid                  bool
   MetadataTypeGuidBuffer []byte
   IMetadataTypeGuid      uint32
   CBPolicyData           uint32
   PolicyDataBuffer       []byte
   IPolicyData            uint32
}

type PolicyMetadataList struct {
   MetadataObject PolicyMetadataObject
   Next           *PolicyMetadataList
}

type PolicyMetadata struct {
   Valid                      bool
   PolicyMetadataObjectsCount uint32
   PolicyMetadataObjectsList  *PolicyMetadataList
}

type RemovalDate struct {
   Valid       bool
   RemovalDate uint32
}

type GlobalRequirements struct {
   Valid                        bool
   MinimumEnvironment           MinimumEnvironment
   SerialNumber                 SerialNumber
   Rights                       Rights
   Priority                     Priority
   SourceID                     SourceID
   RestrictedSourceID           RestrictedSourceID
   Expiration                   Expiration
   IssueDate                    IssueDate
   GracePeriod                  GracePeriod
   Metering                     Metering
   ExpirationAfterUse           ExpirationAfterFirstUse
   ExpirationAfterStore         ExpirationAfterFirstStore
   InclusionList                InclusionList
   RevocationInformationVersion RevocationInformationVersion
   DomainID                     DomainID
   EmbeddingBehavior            EmbeddingBehavior
   UnknownObjects               *UnknownObject
   PolicyMetadata               PolicyMetadata
   RemovalDate                  RemovalDate
}

type Playcount = Dword

type MinimumOutputProtectionLevels struct {
   Valid                    bool
   CompressedDigitalVideo   uint16
   UncompressedDigitalVideo uint16
   AnalogVideo              uint16
   CompressedDigitalAudio   uint16
   UncompressedDigitalAudio uint16
   CBRawData                uint32
   RawData                  []byte
   IRawData                 uint32
}

type OutputConfiguration struct {
   Valid            bool
   GuidBuffer       []byte
   IGuid            uint32
   CBConfigData     uint32
   ConfigDataBuffer []byte
   IConfigData      uint32
}

type VideoOutputConfiguration = OutputConfiguration
type AudioOutputConfiguration = OutputConfiguration

type OutputConfigurationList struct {
   Config OutputConfiguration
   Next   *OutputConfigurationList
}

type VideoOutputConfigurationList = OutputConfigurationList
type AudioOutputConfigurationList = OutputConfigurationList

type ExplicitOutputProtection struct {
   Valid                    bool
   OutputProtectionIDsCount uint32
   CBRawData                uint32
   RawData                  []byte
   IRawData                 uint32
   OutputConfigurationList  *OutputConfigurationList
}

type ExplicitAnalogVideoProtection = ExplicitOutputProtection
type ExplicitDigitalAudioProtection = ExplicitOutputProtection

type PlaybackRights struct {
   Valid                                   bool
   PlayCount                               Playcount
   Opl                                     MinimumOutputProtectionLevels
   ContainerExplicitAnalogVideoProtection  ExplicitAnalogVideoProtection
   ContainerExplicitDigitalAudioProtection ExplicitDigitalAudioProtection
   UnknownObjects                          *UnknownObject
   UnknownContainer                        UnknownContainer
}

type CopyToPC struct {
   Valid bool
}

type CopyCount = DwordVersioned
type CopyProtectionLevel = uint16

type CopyRights struct {
   Valid               bool
   Version             uint32
   CopyCount           CopyCount
   CopyProtectionLevel CopyProtectionLevel
   MoveEnabler         MoveEnabler
   UnknownObjects      *UnknownObject
   UnknownContainer    UnknownContainer
}

type PlaylistBurnRestrictions struct {
   Valid                  bool
   MaxPlaylistBurnCount   uint32
   PlaylistBurnTrackCount uint32
}

type PlaylistBurnRights struct {
   Valid          bool
   Restrictions   PlaylistBurnRestrictions
   UnknownObjects *UnknownObject
}

type RsaPubkey struct {
   Valid         bool
   Exponent      uint32
   CBModulus     uint16
   ModulusBuffer []byte
   IModulus      uint32
}

type RsaLicenseGranterKey = RsaPubkey

type UserID struct {
   Valid    bool
   CBUserID uint32
   UserID   []byte
   IUserID  uint32
}

type Revocation struct {
   Valid                bool
   RsaLicenseGranterKey RsaLicenseGranterKey
   UserID               UserID
}

type ContentKey struct {
   Valid                   bool
   GuidKeyID               []byte
   IGuidKeyID              uint32
   SymmetricCipherType     uint16
   KeyEncryptionCipherType uint16
   CBEncryptedKey          uint16
   EncryptedKeyBuffer      []byte
   IEncryptedKey           uint32
}

type OptimizedContentKey struct {
   Valid                   bool
   KeyEncryptionCipherType uint16
   CBEncryptedKey          uint16
   EncryptedKeyBuffer      []byte
   IEncryptedKey           uint32
}

type EccDeviceKey struct {
   Valid        bool
   EccCurveType uint16
   IKeyData     uint32
   CBKeyData    uint16
   KeyData      []byte
}

type DeviceKey = RsaPubkey

type UplinkKid struct {
   Valid                 bool
   Version               uint32
   GuidUplinkKID         []byte
   IGuidUplinkKID        uint32
   CBChainedCheckSum     uint16
   ChainedCheckSumBuffer []byte
   IChainedCheckSum      uint32
   ChecksumType          uint16
}

type AuxKeyEntry struct {
   Location uint32
   Key      [16]byte
}

type AuxKey struct {
   Valid       bool
   Entries     uint16
   EntriesList []AuxKeyEntry
}

type Uplinkx struct {
   Valid          bool
   GuidUplinkKID  []byte
   IGuidUplinkKID uint32
   CBCheckSum     uint16
   CheckSumBuffer []byte
   ICheckSum      uint32
   CEntries       uint16
   Location       []uint32
   Key            []byte
}

type KeyMaterial struct {
   Valid               bool
   ContentKey          ContentKey
   OptimizedContentKey OptimizedContentKey
   DeviceKey           DeviceKey
   ECCKey              EccDeviceKey
   UplinkKid           UplinkKid
   AuxKey              AuxKey
   UplinkX             Uplinkx
}

type Signature struct {
   Valid           bool
   Type            uint16
   SignatureBuffer []byte
   ISignature      uint32
   CBSignature     uint16
}

type OuterContainer struct {
   Valid                         bool
   ContainerGlobalPolicies       GlobalRequirements
   ContainerPlaybackPolicies     PlaybackRights
   ContainerCopyPolicies         CopyRights
   ContainerCopyToPCPolicies     CopyToPC
   ContainerPlaylistBurnPolicies PlaylistBurnRights
   GenerationNumber              GenerationNumber
   ContainerUnknown              UnknownContainer
   ContainerRevocation           Revocation
   ContainerKeys                 KeyMaterial
   Signature                     Signature
}

type License struct {
   RightsIdBuffer   []byte
   IRightsId        uint32
   Version          uint32
   SignedDataBuffer []byte
   ISignedData      uint32
   CBSignedData     uint32
   ContainerOuter   OuterContainer
   XMRLic           []byte
   CBXMRLic         uint32
}
