package xml

import (
   "encoding/base64"
   "encoding/xml"
   "errors"
)

type WrmHeaderData struct { // Renamed from DATA
   ProtectInfo ProtectInfo `xml:"PROTECTINFO"`
   Kid         Bytes       `xml:"KID"`
}

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

type Bytes []byte

func (e *Envelope) Marshal() ([]byte, error) {
   return xml.Marshal(e)
}

type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body     `xml:"soap:Body"`
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

type EnvelopeResponse struct {
   Body Body
}

type Signature struct {
   SignedInfo     SignedInfo
   SignatureValue Bytes
}

type Reference struct {
   Uri         string `xml:"URI,attr"`
   DigestValue Bytes
}

type CipherData struct {
   CipherValue Bytes
}

type CertificateChains struct {
   CertificateChain Bytes
}

type AcquireLicense struct {
   XmlNs     string    `xml:"xmlns,attr"`
   Challenge Challenge `xml:"challenge"`
}

type Algorithm struct {
   Algorithm string `xml:"Algorithm,attr"`
}

type Challenge struct {
   Challenge InnerChallenge
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"`
}

func (d *Data) Marshal() ([]byte, error) {
   return xml.Marshal(d)
}

type Data struct {
   CertificateChains CertificateChains
   Features          Features
}

type EncryptedData struct {
   XmlNs            string `xml:"xmlns,attr"`
   Type             string `xml:"Type,attr"`
   EncryptionMethod Algorithm
   KeyInfo          KeyInfo
   CipherData       CipherData
}

type EncryptedKey struct {
   XmlNs            string `xml:"xmlns,attr"`
   EncryptionMethod Algorithm
   CipherData       CipherData
   KeyInfo          EncryptedKeyInfo
}

type EncryptedKeyInfo struct { // Renamed from KeyInfo
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string
}

type Feature struct {
   Name string `xml:",attr"`
}

type Features struct {
   Feature Feature
}

type InnerChallenge struct { // Renamed from Challenge
   XmlNs     string `xml:"xmlns,attr"`
   La        La
   Signature Signature
}

type KeyInfo struct { // This is the chosen "KeyInfo" type
   XmlNs        string `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey
}

func (l *La) Marshal() ([]byte, error) {
   return xml.Marshal(l)
}

type La struct {
   XMLName       xml.Name `xml:"LA"`
   XmlNs         string   `xml:"xmlns,attr"`
   Id            string   `xml:"Id,attr"`
   Version       string
   ContentHeader ContentHeader
   EncryptedData EncryptedData
}

type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

func (s *SignedInfo) Marshal() ([]byte, error) {
   return xml.Marshal(s)
}

type SignedInfo struct {
   XmlNs     string `xml:"xmlns,attr"`
   Reference Reference
}

type WrmHeader struct {
   XmlNs   string        `xml:"xmlns,attr"`
   Version string        `xml:"version,attr"`
   Data    WrmHeaderData `xml:"DATA"`
}
