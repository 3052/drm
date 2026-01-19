package bcert

const (
   BcertChainHeaderTag   = 0x43484149
   BcertCertHeaderTag    = 0x54524543
   BcertCurrentVersion   = 1
   BcertMaxCertsPerChain = 6
   SHA256DigestSize      = 32
   ECCP256PointSize      = 64
   ECCP256IntegerSize    = 32
   ECDSAP256SigSize      = 64
   ObjectHeaderLen       = 8
)

const (
   ObjTypeBasic            = 0x0001
   ObjTypeDomain           = 0x0002
   ObjTypePC               = 0x0003
   ObjTypeDevice           = 0x0004
   ObjTypeFeature          = 0x0005
   ObjTypeKey              = 0x0006
   ObjTypeManufacturer     = 0x0007
   ObjTypeSignature        = 0x0008
   ObjTypeSilverlight      = 0x0009
   ObjTypeMetering         = 0x000A
   ObjTypeExtDataSigKey    = 0x000B
   ObjTypeExtDataContainer = 0x000C
   ObjTypeExtDataSig       = 0x000D
   ObjTypeHWID             = 0x000E
   ObjTypeServer           = 0x000F
   ObjTypeSecurityVer      = 0x0010
   ObjTypeSecurityVer2     = 0x0011
)

const (
   FlagMustUnderstand = 0x0001
   FlagContainer      = 0x0002
)

const (
   CertTypeUnknown       = 0x00000000
   CertTypePC            = 0x00000001
   CertTypeDevice        = 0x00000002
   CertTypeDomain        = 0x00000003
   CertTypeIssuer        = 0x00000004
   CertTypeCRLSigner     = 0x00000005
   CertTypeService       = 0x00000006
   CertTypeSilverlight   = 0x00000007
   CertTypeApplication   = 0x00000008
   CertTypeMetering      = 0x00000009
   CertTypeKeyFileSigner = 0x0000000A
   CertTypeServer        = 0x0000000B
   CertTypeLicenseSigner = 0x0000000C
)

const (
   SecurityLevel150  = 150
   SecurityLevel2000 = 2000
   SecurityLevel3000 = 3000
)

const (
   KeyTypeECC256                               = 0x0001
   KeyUsageUnknown                             = 0x00000000
   KeyUsageSign                                = 0x00000001
   KeyUsageEncryptKey                          = 0x00000002
   KeyUsageSignCRL                             = 0x00000003
   KeyUsageIssuerAll                           = 0x00000004
   KeyUsageIssuerIndiv                         = 0x00000005
   KeyUsageIssuerDevice                        = 0x00000006
   KeyUsageIssuerLink                          = 0x00000007
   KeyUsageIssuerDomain                        = 0x00000008
   KeyUsageIssuerSilverlight                   = 0x00000009
   KeyUsageIssuerApplication                   = 0x0000000A
   KeyUsageIssuerCRL                           = 0x0000000B
   KeyUsageIssuerMetering                      = 0x0000000C
   KeyUsageIssuerSignKeyfile                   = 0x0000000D
   KeyUsageSignKeyfile                         = 0x0000000E
   KeyUsageIssuerServer                        = 0x0000000F
   KeyUsageEncryptKeySampleProtectionRC4       = 0x00000010
   KeyUsageIssuerSignLicense                   = 0x00000012
   KeyUsageSignLicense                         = 0x00000013
   KeyUsageSignResponse                        = 0x00000014
   KeyUsagePRNDEncryptKey                      = 0x00000015
   KeyUsageEncryptKeySampleProtectionAES128CTR = 0x00000016
   SignatureTypeP256                           = 0x0001
)

const (
   FeatureTransmitter       = 0x00000001
   FeatureReceiver          = 0x00000002
   FeatureSharedCertificate = 0x00000003
   FeatureSecureClock       = 0x00000004
   FeatureAntirollbackClock = 0x00000005
   FeatureSupportsCRLS      = 0x00000009
   FlagExtDataPresent       = 0x00000001
)
