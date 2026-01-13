package playReady

import (
   "encoding/binary"
   "errors"
   "fmt"
)

// ManufacturerData holds the properly parsed manufacturer data from the certificate,
// including flags and three distinct name/number fields.
type ManufacturerData struct {
   Flags            uint32
   ManufacturerName []byte
   ModelName        []byte
   ModelNumber      []byte
}

// decode populates the ManufacturerData by parsing the flags and three length-prefixed byte arrays.
func (m *ManufacturerData) decode(data []byte) error {
   // --- Parse Flags ---
   if len(data) < 4 {
      return fmt.Errorf("manufacturer data too short for flags: expected at least 4 bytes, got %d", len(data))
   }
   m.Flags = binary.BigEndian.Uint32(data)
   data = data[4:] // Advance past the flags

   // Helper function to read a length-prefixed byte array
   readByteArray := func(d []byte) ([]byte, []byte, error) {
      if len(d) < 4 {
         return nil, nil, fmt.Errorf("data too short for length prefix: expected 4 bytes, got %d", len(d))
      }
      length := binary.BigEndian.Uint32(d)
      d = d[4:]
      if uint32(len(d)) < length {
         return nil, nil, fmt.Errorf("data too short for value: expected %d bytes, got %d", length, len(d))
      }
      return d[length:], d[:length], nil
   }

   var err error
   var value []byte

   // --- Parse Manufacturer Name ---
   data, value, err = readByteArray(data)
   if err != nil {
      return fmt.Errorf("failed to read manufacturer name: %w", err)
   }
   m.ManufacturerName = value

   // --- Parse Model Name ---
   data, value, err = readByteArray(data)
   if err != nil {
      return fmt.Errorf("failed to read model name: %w", err)
   }
   m.ModelName = value

   // --- Parse Model Number ---
   _, value, err = readByteArray(data)
   if err != nil {
      return fmt.Errorf("failed to read model number: %w", err)
   }
   m.ModelNumber = value

   return nil
}

// encode returns the serialized byte representation of the ManufacturerData.
func (m *ManufacturerData) encode() []byte {
   data := make([]byte, 0, m.size())
   data = binary.BigEndian.AppendUint32(data, m.Flags)
   data = binary.BigEndian.AppendUint32(data, uint32(len(m.ManufacturerName)))
   data = append(data, m.ManufacturerName...)
   data = binary.BigEndian.AppendUint32(data, uint32(len(m.ModelName)))
   data = append(data, m.ModelName...)
   data = binary.BigEndian.AppendUint32(data, uint32(len(m.ModelNumber)))
   data = append(data, m.ModelNumber...)
   return data
}

// size returns the byte size of the serialized ManufacturerData.
func (m *ManufacturerData) size() int {
   return 4 + // Flags
      4 + len(m.ManufacturerName) +
      4 + len(m.ModelName) +
      4 + len(m.ModelNumber)
}

// ftlv wraps the ManufacturerData in an Ftlv structure for serialization.
func (m *ManufacturerData) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, m.encode())
}

// CertFeatures defines the features supported by the certificate.
type CertFeatures struct {
   Entries  uint32
   Features []uint32
}

func (c *CertFeatures) New(Type uint32) {
   c.Entries = 1
   c.Features = []uint32{Type}
}

func (c *CertFeatures) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint32(data, c.Entries)
   for _, feature := range c.Features {
      data = binary.BigEndian.AppendUint32(data, feature)
   }
   return data
}

// It returns the number of bytes consumed.
func (c *CertFeatures) decode(data []byte) int {
   c.Entries = binary.BigEndian.Uint32(data)
   n := 4
   c.Features = make([]uint32, c.Entries)
   for i := range c.Entries {
      c.Features[i] = binary.BigEndian.Uint32(data[n:])
      n += 4
   }
   return n
}

func (c *CertFeatures) size() int {
   n := 4 // entries
   n += 4 * len(c.Features)
   return n
}

func (c *CertFeatures) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.Append(nil))
}

// CertSignature holds the signature information of a certificate.
type CertSignature struct {
   SignatureType   uint16
   SignatureLength uint16
   // The actual signature bytes
   Signature    []byte
   IssuerLength uint32
   // The public key of the issuer that signed this certificate
   IssuerKey []byte
}

func (c *CertSignature) decode(data []byte) error {
   c.SignatureType = binary.BigEndian.Uint16(data)
   data = data[2:]
   c.SignatureLength = binary.BigEndian.Uint16(data)
   if c.SignatureLength != 64 {
      return errors.New("signature length invalid")
   }
   data = data[2:]
   c.Signature = data[:c.SignatureLength]
   data = data[c.SignatureLength:]
   c.IssuerLength = binary.BigEndian.Uint32(data)
   if c.IssuerLength != 512 {
      return errors.New("issuer length invalid")
   }
   data = data[4:]
   c.IssuerKey = data[:c.IssuerLength/8]
   return nil
}

func (c *CertSignature) New(signature, modelKey []byte) error {
   c.SignatureType = 1 // required
   c.SignatureLength = 64
   if len(signature) != 64 {
      return errors.New("signature length invalid")
   }
   c.Signature = signature
   c.IssuerLength = 512
   if len(modelKey) != 64 {
      return errors.New("model key length invalid")
   }
   c.IssuerKey = modelKey
   return nil
}

func (c *CertSignature) encode() []byte {
   data := binary.BigEndian.AppendUint16(nil, c.SignatureType)
   data = binary.BigEndian.AppendUint16(data, c.SignatureLength)
   data = append(data, c.Signature...)
   data = binary.BigEndian.AppendUint32(data, c.IssuerLength)
   return append(data, c.IssuerKey...)
}

func (c *CertSignature) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.encode())
}

func (c *CertSignature) size() int {
   n := 2  // signatureType
   n += 2  // signatureLength
   n += 64 // signature
   n += 4  // issuerLength
   n += 64 // issuerKey
   return n
}

// CertificateInfo contains metadata about the certificate.
type CertificateInfo struct {
   CertificateId [16]byte
   SecurityLevel uint32
   Flags         uint32
   InfoType      uint32
   Digest        [32]byte
   Expiry        uint32
   ClientId      [16]byte // Client ID (can be used for license binding)
}

func (c *CertificateInfo) decode(data []byte) {
   c.CertificateId = [16]byte(data)
   data = data[16:]
   c.SecurityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.InfoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.Digest = [32]byte(data)
   data = data[32:]
   c.Expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.ClientId = [16]byte(data)
}

func (c *CertificateInfo) New(securityLevel uint32, digest []byte) {
   c.Digest = [32]byte(digest)
   // required, Max uint32, effectively never expires
   c.Expiry = 4294967295
   // required
   c.InfoType = 2
   c.SecurityLevel = securityLevel
}

func (c *CertificateInfo) encode() []byte {
   data := c.CertificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.SecurityLevel)
   data = binary.BigEndian.AppendUint32(data, c.Flags)
   data = binary.BigEndian.AppendUint32(data, c.InfoType)
   data = append(data, c.Digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.Expiry)
   return append(data, c.ClientId[:]...)
}

func (c *CertificateInfo) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, c.encode())
}

// KeyData holds information about a single key within the KeyInfo section.
type KeyData struct {
   KeyType   uint16
   Length    uint16
   Flags     uint32
   PublicKey [64]byte // ECDSA P256 public key (X and Y coordinates)
   Usage     CertFeatures
}

func (k *KeyData) decode(data []byte) int {
   k.KeyType = binary.BigEndian.Uint16(data)
   n := 2
   k.Length = binary.BigEndian.Uint16(data[n:])
   n += 2
   k.Flags = binary.BigEndian.Uint32(data[n:])
   n += 4
   n += copy(k.PublicKey[:], data[n:])
   n += k.Usage.decode(data[n:])
   return n
}

func (k *KeyData) New(PublicKey []byte, Type uint32) {
   k.Length = 512 // required
   copy(k.PublicKey[:], PublicKey)
   k.Usage.New(Type)
}

func (k *KeyData) Append(data []byte) []byte {
   data = binary.BigEndian.AppendUint16(data, k.KeyType)
   data = binary.BigEndian.AppendUint16(data, k.Length)
   data = binary.BigEndian.AppendUint32(data, k.Flags)
   data = append(data, k.PublicKey[:]...)
   return k.Usage.Append(data)
}

func (k *KeyData) size() int {
   n := 2 // keyType
   n += 2 // length
   n += 4 // flags
   n += len(k.PublicKey)
   n += k.Usage.size()
   return n
}

// KeyInfo contains public key information for the certificate.
type KeyInfo struct {
   Entries uint32 // can be 1 or 2
   Keys    []KeyData
}

func (k *KeyInfo) decode(data []byte) {
   k.Entries = binary.BigEndian.Uint32(data)
   data = data[4:]
   k.Keys = make([]KeyData, k.Entries)
   for i := range k.Entries {
      var key KeyData
      n := key.decode(data)
      k.Keys[i] = key
      data = data[n:] // Advance data slice for the next key
   }
}

func (k *KeyInfo) New(encryptSignKey []byte) {
   k.Entries = 2 // required
   k.Keys = make([]KeyData, 2)
   k.Keys[0].New(encryptSignKey, 1)
   k.Keys[1].New(encryptSignKey, 2)
}

func (k *KeyInfo) encode() []byte {
   data := binary.BigEndian.AppendUint32(nil, k.Entries)
   for _, key := range k.Keys {
      data = key.Append(data)
   }
   return data
}

func (k *KeyInfo) size() int {
   n := 4 // entries
   for _, key := range k.Keys {
      n += key.size()
   }
   return n
}

func (k *KeyInfo) ftlv(Flag, Type uint16) *Ftlv {
   return newFtlv(Flag, Type, k.encode())
}
