package xml

import (
   "encoding/base64"
   "encoding/xml"
   "errors"
)

// Bytes is a custom type for handling base64 encoded byte slices in XML.
type Bytes []byte

func (b Bytes) MarshalText() ([]byte, error) {
   return base64.StdEncoding.AppendEncode(nil, b), nil
}

func (b *Bytes) UnmarshalText(data []byte) error {
   var err error
   *b, err = base64.StdEncoding.AppendDecode(nil, data)
   if err != nil {
      return err
   }
   return nil
}

// Envelope is the top-level structure for a SOAP request.
type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body     `xml:"soap:Body"`
}

func (e *Envelope) Marshal() ([]byte, error) {
   return xml.Marshal(e)
}

// EnvelopeResponse is the top-level structure for a SOAP response.
type EnvelopeResponse struct {
   Body Body
}

func (e *EnvelopeResponse) Unmarshal(data []byte) error {
   err := xml.Unmarshal(data, e)
   if err != nil {
      return err
   }
   if e.Body.Fault != nil {
      return errors.New(e.Body.Fault.Fault)
   }
   return nil
}

// Body contains the main content of the SOAP message.
type Body struct {
   AcquireLicense         *AcquireLicense
   AcquireLicenseResponse *struct {
      AcquireLicenseResult struct {
         Response struct {
            LicenseResponse struct {
               Licenses struct {
                  License Bytes
               }
            }
         }
      }
   }
   Fault *struct {
      Fault string `xml:"faultstring"`
   }
}

// AcquireLicense wraps the license challenge.
type AcquireLicense struct {
   XmlNs     string    `xml:"xmlns,attr"`
   Challenge Challenge `xml:"challenge"`
}

type Challenge struct {
   Challenge InnerChallenge
}

// InnerChallenge contains the signed license acquisition data.
type InnerChallenge struct {
   XmlNs     string `xml:"xmlns,attr"`
   La        *La
   Signature Signature
}

// La represents the License Acquisition challenge structure.
type La struct {
   XMLName       xml.Name `xml:"LA"`
   XmlNs         string   `xml:"xmlns,attr"`
   Id            string   `xml:"Id,attr"`
   Version       string
   ContentHeader ContentHeader
   EncryptedData EncryptedData
}

func (l *La) Marshal() ([]byte, error) {
   return xml.Marshal(l)
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"`
}

type WrmHeader struct {
   XmlNs   string        `xml:"xmlns,attr"`
   Version string        `xml:"version,attr"`
   Data    WrmHeaderData `xml:"DATA"`
}

type WrmHeaderData struct {
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
   Kid         Bytes       `xml:"KID"` // FIXME this can be a slice
}

type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

type EncryptedData struct {
   XmlNs            string `xml:"xmlns,attr"`
   Type             string `xml:"Type,attr"`
   EncryptionMethod Algorithm
   KeyInfo          KeyInfo
   CipherData       CipherData
}

type Algorithm struct {
   Algorithm string `xml:"Algorithm,attr"`
}

// KeyInfo contains information about the encrypted key.
type KeyInfo struct {
   XmlNs        string `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey
}

type EncryptedKey struct {
   XmlNs            string `xml:"xmlns,attr"`
   EncryptionMethod Algorithm
   CipherData       CipherData
   KeyInfo          EncryptedKeyInfo
}

// EncryptedKeyInfo provides metadata for the encrypted key.
type EncryptedKeyInfo struct {
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string
}

type CipherData struct {
   CipherValue Bytes
}

// Data is used to marshal the certificate chain and features into XML.
type Data struct {
   CertificateChains CertificateChains
   Features          Features
}

func (d *Data) Marshal() ([]byte, error) {
   return xml.Marshal(d)
}

type CertificateChains struct {
   CertificateChain Bytes
}

type Features struct {
   Feature Feature
}

type Feature struct {
   Name string `xml:",attr"`
}

// Signature contains the digital signature of the challenge.
type Signature struct {
   SignedInfo     SignedInfo
   SignatureValue Bytes
}

// SignedInfo is the element that is digitally signed.
// REVERTED to original, working structure.
type SignedInfo struct {
   XmlNs     string `xml:"xmlns,attr"`
   Reference Reference
}

func (s *SignedInfo) Marshal() ([]byte, error) {
   return xml.Marshal(s)
}

// Reference specifies a digest value.
// REVERTED to original, working structure.
type Reference struct {
   Uri         string `xml:"URI,attr"`
   DigestValue Bytes
}
