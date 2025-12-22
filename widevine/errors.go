package widevine

import (
   "41.neocities.org/protobuf"
   "strconv"
   "strings"
)

// LicenseError reflects the structure of the Widevine LicenseError protobuf.
type LicenseError struct {
   ErrorCode *protobuf.Field
}

// Error implements the standard Go error interface.
func (le *LicenseError) Error() string {
   if le.ErrorCode == nil {
      return "widevine license error: unknown code"
   }
   var sb strings.Builder
   sb.WriteString("widevine license error: code ")
   sb.WriteString(strconv.FormatUint(le.ErrorCode.Numeric, 10))
   return sb.String()
}

// decodeErrorFromMessage constructs a LicenseError struct from a pre-parsed protobuf message.
func decodeErrorFromMessage(message protobuf.Message) error {
   errorCode, _ := message.Field(1)
   return &LicenseError{
      ErrorCode: errorCode,
   }
}
