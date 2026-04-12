// errors.go
package widevine

import (
   "41.neocities.org/protobuf"
   "fmt"
)

// Error implements the standard Go error interface.
func (le *LicenseError) Error() string {
   if le.ErrorCode == nil {
      return "widevine license error: unknown code"
   }
   return fmt.Sprint("widevine license error: code ", le.ErrorCode.Numeric)
}

// LicenseError reflects the structure of the Widevine LicenseError protobuf.
type LicenseError struct {
   ErrorCode *protobuf.Field
}

// decodeErrorFromMessage constructs a LicenseError struct from a pre-parsed
// protobuf message
func decodeErrorFromMessage(message protobuf.Message) error {
   errorCode, _ := message.Field(1)
   return &LicenseError{
      ErrorCode: errorCode,
   }
}
