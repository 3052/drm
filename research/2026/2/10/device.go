package main

import (
   "bytes"
   "encoding/base64"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "io"
   "log"
   "net/http"
   "os"
)

// Example usage
func main() {
   data, err := os.ReadFile("device.json")
   if err != nil {
      panic(err)
   }
   var site struct {
      Pssh string
      Url  string
   }
   err = json.Unmarshal(data, &site)
   if err != nil {
      panic(err)
   }
   certificateBytes, err := GetServiceCertificate(site.Url)
   if err != nil {
      panic(err)
   }
   device := NewRemoteDevice()
   session := &Session{PSSH: site.Pssh}
   // Optionally set service certificate
   device.SetServiceCertificate(session, certificateBytes)
   // Get license challenge
   challenge, err := device.GetLicenseChallenge(session, "servicename")
   if err != nil {
      log.Fatalf("Failed to get challenge: %v", err)
   }
   if challenge != nil {
      fmt.Println(base64.StdEncoding.EncodeToString(challenge))
      // Send challenge to license server and get response...
      licenseResponse, err := sendToLicenseServer(site.Url, challenge)
      if err != nil {
         panic(err)
      }
      // Parse the license response
      err = device.ParseLicense(session, licenseResponse)
      if err != nil {
         panic(err)
      }
   }
   for _, k := range session.Keys {
      fmt.Printf("KID: %x, Key: %x\n", k.KID, k.Key)
   }
}

func GetServiceCertificate(licenseURL string) ([]byte, error) {
   // Standard Widevine service certificate request payload
   // This is a protobuf message requesting the certificate
   certRequest := []byte{0x08, 0x04}
   req, err := http.NewRequest("POST", licenseURL, bytes.NewBuffer(certRequest))
   if err != nil {
      return nil, err
   }
   req.Header.Set("Content-Type", "application/octet-stream")
   res, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer res.Body.Close()
   return io.ReadAll(res.Body)
}

func sendToLicenseServer(licenseURL string, challenge []byte) ([]byte, error) {
   req, err := http.NewRequest("POST", licenseURL, bytes.NewBuffer(challenge))
   if err != nil {
      return nil, err
   }
   req.Header.Set("Content-Type", "application/octet-stream")
   res, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer res.Body.Close()
   return io.ReadAll(res.Body)
}

// Hardcoded configuration values from YAML (only the ones actually used)
const (
   Host      = "https://widevinel1apil.vercel.app"
   SecretKey = "free_l1_widevine_key"
   Username  = "free_l1_user_api"
)

// ContentKey represents a decryption key
type ContentKey struct {
   KID     []byte
   KeyType string
   Key     []byte
}

// Session holds session-related data
type Session struct {
   PSSH                    string
   SignedDeviceCertificate string
   PrivacyMode             bool
   Keys                    []ContentKey
}

// ChallengeResponse represents the API response for get_challenge
type ChallengeResponse struct {
   SessionID string   `json:"sessionId"`
   Data      string   `json:"data"`
   Keys      []KeyDTO `json:"keys,omitempty"`
}

// KeyDTO represents a key from the API response
type KeyDTO struct {
   KeyID string `json:"key_id"`
   Key   string `json:"key"`
}

// RemoteDevice represents a remote Widevine device
type RemoteDevice struct {
   APISessionID string
   InitData     string
   ServiceName  string
}

// NewRemoteDevice creates a new RemoteDevice
func NewRemoteDevice() *RemoteDevice {
   return &RemoteDevice{}
}

// SetServiceCertificate applies a service certificate to the session
func (rd *RemoteDevice) SetServiceCertificate(session *Session, certificate []byte) {
   session.SignedDeviceCertificate = base64.StdEncoding.EncodeToString(certificate)
   session.PrivacyMode = true
}

// GetLicenseChallenge retrieves a license challenge from the remote API
// Returns the challenge bytes, or nil if keys were cached (check session.Keys)
func (rd *RemoteDevice) GetLicenseChallenge(session *Session, service string) ([]byte, error) {
   rd.InitData = session.PSSH
   rd.ServiceName = service

   params := map[string]interface{}{
      "init_data":           session.PSSH,
      "service_certificate": session.SignedDeviceCertificate,
      "service":             service,
   }

   res, err := rd.apiRequest("get_challenge", params)
   if err != nil {
      return nil, fmt.Errorf("unable to get license challenge: %w", err)
   }
   defer res.Body.Close()

   if res.StatusCode != http.StatusOK {
      body, _ := io.ReadAll(res.Body)
      return nil, fmt.Errorf("unable to get license challenge: %s", string(body))
   }

   var challengeResp ChallengeResponse
   if err := json.NewDecoder(res.Body).Decode(&challengeResp); err != nil {
      return nil, fmt.Errorf("failed to decode response: %w", err)
   }

   // Check if keys are returned from CDM cache
   if len(challengeResp.Keys) > 0 {
      log.Println(" + Keys from cdm cache")
      for _, kidkey := range challengeResp.Keys {
         kid, _ := hex.DecodeString(kidkey.KeyID)
         key, _ := hex.DecodeString(kidkey.Key)
         session.Keys = append(session.Keys, ContentKey{
            KID:     kid,
            KeyType: "CONTENT",
            Key:     key,
         })
      }
      return nil, nil
   }

   rd.APISessionID = challengeResp.SessionID
   challenge, err := base64.StdEncoding.DecodeString(challengeResp.Data)
   if err != nil {
      return nil, fmt.Errorf("failed to decode challenge: %w", err)
   }

   return challenge, nil
}

// ParseLicense parses the license response and extracts keys
func (rd *RemoteDevice) ParseLicense(session *Session, licenseRes []byte) error {
   params := map[string]interface{}{
      "lic_resp":  base64.StdEncoding.EncodeToString(licenseRes),
      "sessionId": rd.APISessionID,
      "service":   rd.ServiceName,
   }

   res, err := rd.apiRequest("get_keys", params)
   if err != nil {
      return fmt.Errorf("unable to get keys: %w", err)
   }
   defer res.Body.Close()

   if res.StatusCode != http.StatusOK {
      body, _ := io.ReadAll(res.Body)
      return fmt.Errorf("unable to get keys: %s", string(body))
   }

   var keysResponse []KeyDTO
   if err := json.NewDecoder(res.Body).Decode(&keysResponse); err != nil {
      return fmt.Errorf("failed to decode keys response: %w", err)
   }

   for _, kidkey := range keysResponse {
      kid, _ := hex.DecodeString(kidkey.KeyID)
      key, _ := hex.DecodeString(kidkey.Key)
      session.Keys = append(session.Keys, ContentKey{
         KID:     kid,
         KeyType: "CONTENT",
         Key:     key,
      })
   }

   return nil
}

// apiRequest makes an HTTP POST request to the API
func (rd *RemoteDevice) apiRequest(method string, params map[string]interface{}) (*http.Response, error) {
   jsonBody, err := json.Marshal(params)
   if err != nil {
      return nil, fmt.Errorf("failed to marshal params: %w", err)
   }

   req, err := http.NewRequest("POST", Host+"/"+method, bytes.NewBuffer(jsonBody))
   if err != nil {
      return nil, fmt.Errorf("failed to create request: %w", err)
   }

   req.Header.Set("Content-Type", "application/json")
   req.Header.Set("X-Username", Username)
   req.Header.Set("X-Secret-Key", SecretKey)

   return http.DefaultClient.Do(req)
}
