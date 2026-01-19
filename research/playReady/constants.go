package bcert

const (
	TagCHAI = 0x43484149
	TagCERT = 0x43455254

	ObjTypeBasic            = 0x0001
	ObjTypeFeature          = 0x0005
	ObjTypeKey              = 0x0006
	ObjTypeSignature        = 0x0007
	ObjTypeDomain           = 0x0008
	ObjTypeDevice           = 0x000A
	ObjTypePC               = 0x000B
	ObjTypeManufacturer     = 0x000D
	ObjTypeSilverlight      = 0x000E
	ObjTypeMetering         = 0x000F
	ObjTypeExtDataSigKey    = 0x0010
	ObjTypeExtDataContainer = 0x0011
	ObjTypeServerType       = 0x0012
	ObjTypeSecurityVersion  = 0x0013
	ObjTypeSecurityVersion2 = 0x0014

	FlagMustUnderstand = 0x0001

	maxAllocationSize = 1024 * 1024
)
