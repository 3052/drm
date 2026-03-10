package playReady

import (
   "41.neocities.org/drm/playReady/xml"
   "bytes"
   "crypto/aes"
   "crypto/ecdsa"
   "crypto/elliptic"
   "crypto/sha256"
   "encoding/binary"
   "errors"
   "github.com/deatil/go-cryptobin/mac"
   "math/big"
   "slices"
)

func (c *Chain) cipherData(key *xmlKey) ([]byte, error) {
   data := xml.Data{
      CertificateChains: xml.CertificateChains{
         CertificateChain: c.Encode(),
      },
      Features: xml.Features{
         Feature: xml.Feature{"AESCBC"}, // SCALABLE
      },
   }
   data1, err := data.Marshal()
   if err != nil {
      return nil, err
   }
   data1, err = aesCBCHandler(data1, key.aesKey(), key.aesIv(), true)
   if err != nil {
      return nil, err
   }
   return append(key.aesIv(), data1...), nil
}

// Encode encodes the Chain into a byte slice.
func (c *Chain) Encode() []byte {
   data := c.magic[:]
   data = binary.BigEndian.AppendUint32(data, c.version)
   data = binary.BigEndian.AppendUint32(data, c.length)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.certCount)
   for _, cert := range c.certs {
      data = append(data, cert.encode()...)
   }
   return data
}

// verify verifies the entire certificate chain.
func (c *Chain) verify() bool {
   // Start verification with the issuer key of the last certificate in the chain.
   modelBase := c.certs[len(c.certs)-1].signatureData.IssuerKey
   for i := len(c.certs) - 1; i >= 0; i-- {
      // Verify each certificate using the public key of its issuer.
      valid := c.certs[i].verify(modelBase[:])
      if !valid {
         return false
      }
      // The public key of the current certificate becomes the issuer key for
      // the next in the chain.
      modelBase = c.certs[i].keyInfo.keys[0].publicKey[:]
   }
   return true
}

// Decode decodes a byte slice into the Chain structure.
func (c *Chain) Decode(data []byte) error {
   n := copy(c.magic[:], data)
   if string(c.magic[:]) != "CHAI" {
      return errors.New("failed to find chain magic")
   }
   data = data[n:]
   c.version = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.length = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.certCount = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.certs = make([]certificate, c.certCount)
   for i := range c.certCount {
      var cert certificate
      n, err := cert.decode(data)
      if err != nil {
         return err
      }
      c.certs[i] = cert
      data = data[n:]
   }
   return nil
}

// Chain represents a chain of certificates.
type Chain struct {
   magic     [4]byte
   version   uint32
   length    uint32
   flags     uint32
   certCount uint32
   certs     []certificate
}

func (l *license) verify(contentIntegrity []byte) error {
   data := l.encode()
   data = data[:len(data)-int(l.signature.Length)]
   block, err := aes.NewCipher(contentIntegrity)
   if err != nil {
      return err
   }
   data = mac.NewCMAC(block, aes.BlockSize).MAC(data)
   if !bytes.Equal(data, l.signature.Data) {
      return errors.New("failed to decrypt the keys")
   }
   return nil
}

func (l *license) encode() []byte {
   data := l.Magic[:]
   data = binary.BigEndian.AppendUint16(data, l.Offset)
   data = binary.BigEndian.AppendUint16(data, l.Version)
   data = append(data, l.RightsID[:]...)
   return append(data, l.OuterContainer.encode()...)
}

func (l *license) decode(data []byte) error {
   n := copy(l.Magic[:], data)
   data = data[n:]
   l.Offset = binary.BigEndian.Uint16(data)
   data = data[2:]
   l.Version = binary.BigEndian.Uint16(data)
   data = data[2:]
   n = copy(l.RightsID[:], data)
   data = data[n:]
   l.OuterContainer.decode(data)
   var n1 int
   for n1 < int(l.OuterContainer.Length)-16 {
      var value ftlv
      n1 += value.decode(l.OuterContainer.Value[n1:])
      switch xmrType(value.Type) {
      case globalPolicyContainerEntryType: // 2
         // Rakuten
      case playbackPolicyContainerEntryType: // 4
         // Rakuten
      case keyMaterialContainerEntryType: // 9
         var n2 int
         for n2 < int(value.Length)-16 {
            var value1 ftlv
            n2 += value1.decode(value.Value[n2:])
            switch xmrType(value1.Type) {
            case contentKeyEntryType: // 10
               l.contentKey = &ContentKey{}
               l.contentKey.decode(value1.Value)
            case deviceKeyEntryType: // 42
               l.eccKey = &eccKey{}
               l.eccKey.decode(value1.Value)
            case auxKeyEntryType: // 81
               l.auxKeyObject = &auxKeys{}
               l.auxKeyObject.decode(value1.Value)
            default:
               return errors.New("FTLV.type")
            }
         }
      case signatureEntryType: // 11
         l.signature = &signature{}
         l.signature.decode(value.Value)
         l.signature.Length = uint16(value.Length)
      default:
         return errors.New("FTLV.type")
      }
   }
   return nil
}

///

// decode decodes a byte slice into the Cert structure.
func (c *certificate) decode(data []byte) (int, error) {
   n := copy(c.magic[:], data)
   if string(c.magic[:]) != "CERT" {
      return 0, errors.New("failed to find cert magic")
   }
   c.version = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.length = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.lengthToSignature = binary.BigEndian.Uint32(data[n:])
   n += 4
   c.rawData = data[n:][:c.length-16]
   n += len(c.rawData)
   var n1 int
   for n1 < len(c.rawData) {
      var value ftlv
      n1 += value.decode(c.rawData[n1:])
      switch value.Type {
      case objTypeBasic:
         c.certificateInfo = &certificateInfo{}
         c.certificateInfo.decode(value.Value)
      case objTypeFeature:
         c.features = &features{}
         c.features.decode(value.Value)
      case objTypeKey:
         c.keyInfo = &keyInfo{}
         c.keyInfo.decode(value.Value)
      case objTypeManufacturer:
         c.manufacturerInfo = &manufacturer{}
         c.manufacturerInfo.decode(value.Value)
      case objTypeSignature:
         c.signatureData = &ecdsaSignature{}
         c.signatureData.decode(value.Value)
      }
   }
   return n, nil
}

// verify verifies the signature of the certificate using the provided public
// key.
func (c *certificate) verify(pubKey []byte) bool {
   // Check if the issuer key in the signature matches the provided public key.
   if !bytes.Equal(c.signatureData.IssuerKey, pubKey) {
      return false
   }
   // Reconstruct the ECDSA public key from the byte slice.
   publicKey := ecdsa.PublicKey{
      Curve: elliptic.P256(), // Assuming P256 curve
      X:     new(big.Int).SetBytes(pubKey[:32]),
      Y:     new(big.Int).SetBytes(pubKey[32:]),
   }
   // Get the data that was signed (up to lengthToSignature).
   data := c.encode()
   data = data[:c.lengthToSignature]
   signatureDigest := sha256.Sum256(data)
   // Extract R and S components from the signature data.
   sign := c.signatureData.SignatureData
   r := new(big.Int).SetBytes(sign[:32])
   s := new(big.Int).SetBytes(sign[32:])
   // Verify the signature.
   return ecdsa.Verify(&publicKey, signatureDigest[:], r, s)
}

type certificate struct {
   magic             [4]byte
   version           uint32
   length            uint32
   lengthToSignature uint32
   rawData           []byte
   certificateInfo   *certificateInfo
   features          *features
   keyInfo           *keyInfo
   manufacturerInfo  *manufacturer
   signatureData     *ecdsaSignature
}

// newNoSig initializes a new Cert without signature data.
func (c *certificate) newNoSig(data []byte) {
   copy(c.magic[:], "CERT")
   c.version = 1
   // length = length of raw data + header size (16) + signature size (144)
   c.length = uint32(len(data)) + 16 + 144
   // lengthToSignature = length of raw data + header size (16)
   c.lengthToSignature = uint32(len(data)) + 16
   c.rawData = data
}

// encode encodes the Cert structure into a byte slice.
func (c *certificate) encode() []byte {
   data := c.magic[:]
   data = binary.BigEndian.AppendUint32(data, c.version)
   data = binary.BigEndian.AppendUint32(data, c.length)
   data = binary.BigEndian.AppendUint32(data, c.lengthToSignature)
   return append(data, c.rawData...)
}

type certificateInfo struct {
   certificateId [16]byte
   securityLevel uint32
   flags         uint32
   infoType      uint32
   digest        [32]byte
   expiry        uint32
   // NOTE SOME SERVERS, FOR EXAMPLE
   // rakuten.tv
   // WILL LOCK LICENSE TO THE FIRST DEVICE, USING "ClientId" TO DETECT, SO BE
   // CAREFUL USING A VALUE HERE
   clientId [16]byte
}

func (c *certificateInfo) encode() []byte {
   data := c.certificateId[:]
   data = binary.BigEndian.AppendUint32(data, c.securityLevel)
   data = binary.BigEndian.AppendUint32(data, c.flags)
   data = binary.BigEndian.AppendUint32(data, c.infoType)
   data = append(data, c.digest[:]...)
   data = binary.BigEndian.AppendUint32(data, c.expiry)
   return append(data, c.clientId[:]...)
}

func (c *certificateInfo) New(securityLevel uint32, digest []byte) {
   c.securityLevel = securityLevel
   c.infoType = 2 // Assuming infoType 2 is a standard type
   copy(c.digest[:], digest)
   c.expiry = 4294967295 // Max uint32, effectively never expires
}

func (c *certificateInfo) decode(data []byte) {
   n := copy(c.certificateId[:], data)
   data = data[n:]
   c.securityLevel = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.flags = binary.BigEndian.Uint32(data)
   data = data[4:]
   c.infoType = binary.BigEndian.Uint32(data)
   data = data[4:]
   n = copy(c.digest[:], data)
   data = data[n:]
   c.expiry = binary.BigEndian.Uint32(data)
   data = data[4:]
   copy(c.clientId[:], data)
}

type license struct {
   Magic          [4]byte
   Offset         uint16
   Version        uint16
   RightsID       [16]byte
   OuterContainer ftlv
   contentKey     *ContentKey
   eccKey         *eccKey
   signature      *signature
   auxKeyObject   *auxKeys
}

// CreateLeaf creates a new leaf certificate and adds it to the chain.
func (c *Chain) CreateLeaf(modelKey, signingKey, encryptKey *EcKey) error {
   // Verify that the provided modelKey matches the public key in the chain's
   // first certificate.
   if !bytes.Equal(c.certs[0].keyInfo.keys[0].publicKey[:], modelKey.Public()) {
      return errors.New("zgpriv not for cert")
   }
   // Verify the existing chain's validity.
   if !c.verify() {
      return errors.New("cert is not valid")
   }
   // Assemble raw data for the unsigned certificate.
   var leafData bytes.Buffer
   {
      // Calculate digest for the signing key.
      digest := sha256.Sum256(signingKey.Public())
      // Initialize certificate information.
      var info certificateInfo
      info.New(c.certs[0].certificateInfo.securityLevel, digest[:])
      // Create FTLV (Fixed Tag Length Value) for certificate info.
      var value ftlv
      value.New(1, 1, info.encode())
      leafData.Write(value.encode())
   }
   {
      // Create a new device and its FTLV.
      var device1 device
      device1.New()
      var value ftlv
      value.New(1, 4, device1.encode())
      leafData.Write(value.encode())
   }
   {
      // SCALABLE with SL2000, SUPPORTS_PR3_FEATURES
      feature := features{
         entries:  1,
         features: []uint32{0xD},
      }
      // Create FTLV for features.
      var value ftlv
      value.New(1, 5, feature.encode())
      leafData.Write(value.encode())
   }
   {
      // Initialize key information for signing and encryption keys.
      var key keyInfo
      key.New(signingKey.Public(), encryptKey.Public())
      // Create FTLV for key information.
      var value ftlv
      value.New(1, 6, key.encode())
      leafData.Write(value.encode())
   }
   {
      // Create FTLV for manufacturer information, copying from the existing
      // chain's first cert.
      var value ftlv
      value.New(0, 7, c.certs[0].manufacturerInfo.encode())
      leafData.Write(value.encode())
   }
   // Create an unsigned certificate object.
   var unsignedCert certificate
   unsignedCert.newNoSig(leafData.Bytes())
   {
      // Sign the unsigned certificate's data.
      digest := sha256.Sum256(unsignedCert.encode())
      r, s, err := ecdsa.Sign(Fill('A'), modelKey[0], digest[:])
      if err != nil {
         return err
      }
      sign := append(r.Bytes(), s.Bytes()...)
      // Initialize the signature data for the new certificate.
      var signatureData ecdsaSignature
      signatureData.New(sign, modelKey.Public())
      // Create FTLV for the signature.
      var value ftlv
      value.New(1, 8, signatureData.encode())
      // Append the signature FTLV to the leaf data.
      leafData.Write(value.encode())
   }
   // Update the unsigned certificate's length and rawData.
   unsignedCert.length = uint32(leafData.Len()) + 16
   unsignedCert.rawData = leafData.Bytes()
   // Update the chain's length, certificate count, and insert the new
   // certificate.
   c.length += unsignedCert.length
   c.certCount += 1
   c.certs = slices.Insert(c.certs, 0, unsignedCert)
   return nil
}

func (l *license) decrypt(encrypt EcKey, data []byte) error {
   var envelope xml.EnvelopeResponse
   err := envelope.Unmarshal(data)
   if err != nil {
      return err
   }
   err = l.decode(envelope.
      Body.
      AcquireLicenseResponse.
      AcquireLicenseResult.
      Response.
      LicenseResponse.
      Licenses.
      License,
   )
   if err != nil {
      return err
   }
   if !bytes.Equal(l.eccKey.Value, encrypt.Public()) {
      return errors.New("license response is not for this device")
   }
   err = l.contentKey.decrypt(encrypt[0], l.auxKeyObject)
   if err != nil {
      return err
   }
   return l.verify(l.contentKey.Integrity[:])
}
