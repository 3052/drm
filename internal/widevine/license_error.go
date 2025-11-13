package widevine

import (
   "41.neocities.org/protobuf"
)

// LicenseError reflects the structure of the Widevine LicenseError protobuf.
type LicenseError struct {
   ErrorCode *protobuf.Field
}

// decodeErrorFromMessage constructs a LicenseError struct from a pre-parsed protobuf message.
func decodeErrorFromMessage(message protobuf.Message) (*LicenseError, error) {
   errorCode, _ := message.Field(1)

   return &LicenseError{
      ErrorCode: errorCode,
   }, nil
}
