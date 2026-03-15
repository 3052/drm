// drm_xmr.go
package playReady

const (
   HeaderLength  = (4 * 2) + 16 // Assuming SIZEOF(DRM_ID) == 16
   MagicConstant = 0x584D5200   // 'XMR\0'
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

type EccDeviceKey struct {
   Valid        bool
   EccCurveType uint16
   IKeyData     uint32
   CBKeyData    uint16
   KeyData      []byte
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

type KeyMaterial struct {
   Valid      bool
   ContentKey ContentKey
   ECCKey     EccDeviceKey
   AuxKey     AuxKey
}

type Signature struct {
   Valid           bool
   Type            uint16
   SignatureBuffer []byte
   ISignature      uint32
   CBSignature     uint16
}

type OuterContainer struct {
   Valid         bool
   ContainerKeys KeyMaterial
   Signature     Signature
}

type License struct {
   RightsIdBuffer []byte
   IRightsId      uint32
   Version        uint32
   ContainerOuter OuterContainer
   XMRLic         []byte
   CBXMRLic       uint32
}
