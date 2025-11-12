package widevine

import (
   "41.neocities.org/protobuf"
)

// LicenseError reflects the structure of the Widevine LicenseError protobuf.
type LicenseError struct {
   ErrorCode *protobuf.Field
}

// ParseLicenseError deserializes a LicenseError from the protobuf wire format.
func ParseLicenseError(data []byte) (*LicenseError, error) {
   var message protobuf.Message
   if err := message.Parse(data); err != nil {
      return nil, err
   }

   errorCode, _ := message.Field(1)

   return &LicenseError{
      ErrorCode: errorCode,
   }, nil
}
