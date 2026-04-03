// xml/models.go
package xml

import (
   "encoding/base64"
   "encoding/xml"
)

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

var (
   Marshal   = xml.Marshal
   Unmarshal = xml.Unmarshal
)

type Bytes []byte

type Envelope struct {
   Body    Body     `xml:"soap:Body"`
   Soap    string   `xml:"xmlns:soap,attr"`
   XMLName xml.Name `xml:"soap:Envelope"`
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

type AcquireLicense struct {
   Challenge Challenge `xml:"challenge"`
   XmlNs     string    `xml:"xmlns,attr"`
}

type Challenge struct {
   Challenge InnerChallenge
}

type Signature struct {
   SignatureValue Bytes
   SignedInfo     SignedInfo
}

type Algorithm struct {
   Algorithm string `xml:"Algorithm,attr"`
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"`
}

type CipherData struct {
   CipherValue Bytes
}

type CustomAttributes struct {
   ContentId string `xml:"CONTENTID"`
}

type EnvelopeResponse struct {
   Body Body
}

type CertificateChains struct {
   CertificateChain Bytes
}

type Data struct {
   CertificateChains CertificateChains
   Features          Features
}

type Feature struct {
   Name string `xml:",attr"`
}

type Features struct {
   Feature Feature
}

type InnerChallenge struct {
   La        *La
   Signature Signature
   XmlNs     string `xml:"xmlns,attr"`
}

type SignedInfo struct {
   Reference Reference
   XmlNs     string `xml:"xmlns,attr"`
}

type Reference struct {
   DigestValue Bytes
   Uri         string `xml:"URI,attr"`
}

type KeyInfo struct {
   EncryptedKey EncryptedKey
   XmlNs        string `xml:"xmlns,attr"`
}

type WrmHeaderData struct {
   CustomAttributes *CustomAttributes `xml:"CUSTOMATTRIBUTES"`
   Kid              Bytes             `xml:"KID"`
   ProtectInfo      ProtectInfo       `xml:"PROTECTINFO"`
}

type ProtectInfo struct {
   AlgId  string `xml:"ALGID"`
   KeyLen string `xml:"KEYLEN"`
}

type EncryptedKeyInfo struct {
   KeyName string
   XmlNs   string `xml:"xmlns,attr"`
}

type EncryptedKey struct {
   CipherData       CipherData
   EncryptionMethod Algorithm
   KeyInfo          EncryptedKeyInfo
   XmlNs            string `xml:"xmlns,attr"`
}

type WrmHeader struct {
   Data WrmHeaderData `xml:"DATA"`
   // ATTRIBUTE ORDER MATTERS
   XmlNs   string `xml:"xmlns,attr"`
   Version string `xml:"version,attr"`
}

type La struct {
   ClientTime    int
   ContentHeader ContentHeader
   EncryptedData EncryptedData
   LicenseNonce  Bytes
   Version       string
   XMLName       xml.Name `xml:"LA"`
   // ATTRIBUTE ORDER MATTERS
   XmlNs string `xml:"xmlns,attr"`
   Id    string `xml:"Id,attr"`
}

type EncryptedData struct {
   CipherData       CipherData
   EncryptionMethod Algorithm
   KeyInfo          KeyInfo
   // ATTRIBUTE ORDER MATTERS
   XmlNs string `xml:"xmlns,attr"`
   Type  string `xml:"Type,attr"`
}
