package widevine

// LicenseType defines the type of license being requested.
type LicenseType int32

const (
   // For streaming.
   LicenseType_STREAMING LicenseType = 0
   // For offline playback.
   LicenseType_OFFLINE LicenseType = 1
)

// SignatureAlgorithm defines the algorithm used for the request signature.
type SignatureAlgorithm int32

const (
   // RSASSA-PSS with SHA-1 digest.
   SignatureAlgorithm_RSASSA_PSS_SHA1 SignatureAlgorithm = 1
)
