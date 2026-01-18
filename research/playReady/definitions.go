package playready

import "fmt"

//================================================================================
// Errors
//================================================================================

var (
   ErrBufferTooSmall       = fmt.Errorf("buffer is too small")
   ErrInvalidChainHeader   = fmt.Errorf("invalid chain header tag, expected 'CHAI'")
   ErrInvalidCertHeader    = fmt.Errorf("invalid certificate header tag, expected 'CERT'")
   ErrInvalidObjectHeader  = fmt.Errorf("invalid object header")
   ErrUnknownObjectType    = fmt.Errorf("unknown object type encountered")
   ErrObjectTooLarge       = fmt.Errorf("object length exceeds remaining buffer")
   ErrMustUnderstand       = fmt.Errorf("encountered an object with Must-Understand flag that is not supported")
   ErrUnexpectedEndOfData  = fmt.Errorf("unexpected end of data while parsing")
   ErrInvalidDataAlignment = fmt.Errorf("data is not properly aligned")
)

//================================================================================
// Constants
//================================================================================

// Header tags
const (
   ChainHeaderTag = 0x43484149 // "CHAI"
   CertHeaderTag  = 0x43455254 // "CERT"
)

// Object types from drmbcertformat_generated.h
const (
   ObjTypeBasic            uint16 = 0x0001
   ObjTypeDomain           uint16 = 0x0002
   ObjTypePC               uint16 = 0x0003
   ObjTypeDevice           uint16 = 0x0004
   ObjTypeFeature          uint16 = 0x0005
   ObjTypeKey              uint16 = 0x0006
   ObjTypeManufacturer     uint16 = 0x0007
   ObjTypeSignature        uint16 = 0x0008
   ObjTypeSilverlight      uint16 = 0x0009
   ObjTypeMetering         uint16 = 0x000A
   ObjTypeExtDataSignKey   uint16 = 0x000B
   ObjTypeExtDataContainer uint16 = 0x000C
   ObjTypeExtDataSignature uint16 = 0x000D
   ObjTypeExtDataHWID      uint16 = 0x000E
   ObjTypeServer           uint16 = 0x000F
   ObjTypeSecurityVersion  uint16 = 0x0010
   ObjTypeSecurityVersion2 uint16 = 0x0011
   ObjTypeUnknown          uint16 = 0xFFFD
)

// Object Flags from drmbcertconstants.h and the description tables
const (
   ObjFlagNone           uint16 = 0x0000
   ObjFlagMustUnderstand uint16 = 0x0001
   ObjFlagContainerObj   uint16 = 0x0002
)
