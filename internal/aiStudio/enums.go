package widevine

// LicenseType defines the type of license being requested.
type LicenseType int32

const (
   // For streaming.
   LicenseType_STREAMING LicenseType = 0
   // For offline playback.
   LicenseType_OFFLINE LicenseType = 1
)

// MessageType defines the type of the top-level signed message.
type MessageType int32

const (
   MessageType_LICENSE_REQUEST  MessageType = 0
   MessageType_LICENSE_RESPONSE MessageType = 1
)

// RequestType defines the type of the license request itself.
type RequestType int32

const (
   RequestType_NEW     RequestType = 0
   RequestType_RENEWAL RequestType = 1
)

// KeyType defines the purpose of a key included in the license.
// Values are based on the provided license_protocol.proto.
type KeyType int32

const (
   // Key is for signing.
   KeyType_SIGNING KeyType = 1
   // Key is for content decryption.
   KeyType_CONTENT KeyType = 2
   // Key control block for license renewals.
   KeyType_KEY_CONTROL KeyType = 3
   // Wrapped keys for auxiliary crypto operations.
   KeyType_OPERATOR_SESSION KeyType = 4
)
