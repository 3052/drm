package widevine

// --- Field Numbers ---
const (
   // WidevineCencHeader fields
   WidevineCencHeader_KeyId     uint32 = 2
   WidevineCencHeader_ContentId uint32 = 4

   // SignedMessage fields
   SignedMessage_Type uint32 = 1
   SignedMessage_Msg  uint32 = 2

   // LicenseRequest fields
   LicenseRequest_ContentId   uint32 = 1
   LicenseRequest_Type        uint32 = 2
   LicenseRequest_RequestTime uint32 = 3
   LicenseRequest_KeyId       uint32 = 4
   LicenseRequest_ClientInfo  uint32 = 7

   // ClientInfo fields
   ClientInfo_DeviceModel uint32 = 5

   // License fields
   License_Key uint32 = 3

   // License_Key fields
   License_Key_Id   uint32 = 1
   License_Key_Key  uint32 = 3
   License_Key_Type uint32 = 4
)

// --- Enums ---
const (
   LicenseRequestType_NEW            uint64 = 1
   SignedMessageType_LICENSE_REQUEST uint64 = 1
   SignedMessageType_LICENSE         uint64 = 2
)
