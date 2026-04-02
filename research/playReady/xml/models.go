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

// multiple parents
type Bytes []byte

// zero parents
type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"` // microsoft.com
   Soap    string   `xml:"xmlns:soap,attr"` // microsoft.com
   Body    Body     `xml:"soap:Body"` // microsoft.com
}

// multiple parents
type Body struct {
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
   AcquireLicense *AcquireLicense // microsoft.com
}

// one parent
type AcquireLicense struct {
   XmlNs     string    `xml:"xmlns,attr"` // microsoft.com
   Challenge Challenge `xml:"challenge"` // microsoft.com
}

// one parent
type Challenge struct {
   Challenge InnerChallenge // microsoft.com
}

// one parent
type InnerChallenge struct {
   XmlNs     string `xml:"xmlns,attr"` // microsoft.com
   La        *La // microsoft.com
   Signature Signature // microsoft.com
}

// one parent
type Signature struct {
   SignatureValue Bytes // microsoft.com
   SignedInfo     SignedInfo // microsoft.com
}

// multiple parents
type Algorithm struct {
   Algorithm string `xml:"Algorithm,attr"` // microsoft.com
}

// one parent
type SignedInfo struct {
   XmlNs                  string `xml:"xmlns,attr"` // microsoft.com
   Reference              Reference // microsoft.com
}

// one parent
type Reference struct {
   Uri          string `xml:"URI,attr"` // microsoft.com
   DigestValue  Bytes // microsoft.com
}

// one parent
type WrmHeader struct {
   XmlNs   string        `xml:"xmlns,attr"` // microsoft.com
   Version string        `xml:"version,attr"` // microsoft.com
   Data    WrmHeaderData `xml:"DATA"` // microsoft.com
}

// one parent
type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"` // microsoft.com
}

// one parent
type La struct {
   XMLName       xml.Name `xml:"LA"` // microsoft.com
   XmlNs         string   `xml:"xmlns,attr"` // microsoft.com
   Id            string   `xml:"Id,attr"` // microsoft.com
   Version       string // microsoft.com
   ClientTime int // 9c9media.com
   LicenseNonce  Bytes // 9c9media.com
   ContentHeader ContentHeader // microsoft.com
   EncryptedData EncryptedData // microsoft.com
}

// multiple parent
type CipherData struct {
   CipherValue Bytes // microsoft.com
}

// one parent
type KeyInfo struct {
   XmlNs        string `xml:"xmlns,attr"` // microsoft.com
   EncryptedKey EncryptedKey
}

// one parent
type EncryptedData struct {
   XmlNs            string `xml:"xmlns,attr"` // microsoft.com
   Type             string `xml:"Type,attr"` // microsoft.com
   EncryptionMethod Algorithm // microsoft.com
   KeyInfo          KeyInfo // microsoft.com
   CipherData       CipherData
}

// one parent
type WrmHeaderData struct {
   Kid              Bytes             `xml:"KID"` // microsoft.com
   CustomAttributes *CustomAttributes `xml:"CUSTOMATTRIBUTES"` // 9c9media.com
   ProtectInfo      ProtectInfo       `xml:"PROTECTINFO"`
}

// one parent
type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"` // microsoft.com
   AlgId  string `xml:"ALGID"` // microsoft.com
}

// one parent
type EncryptedKey struct {
   XmlNs            string           `xml:"xmlns,attr"` // microsoft.com
   EncryptionMethod Algorithm
   KeyInfo          EncryptedKeyInfo
   CipherData       CipherData
}

// one parent
type EncryptedKeyInfo struct {
   XmlNs   string `xml:"xmlns,attr"` // microsoft.com
   KeyName string // microsoft.com
}

// one parent
type CustomAttributes struct {
   ContentId string `xml:"CONTENTID"` // 9c9media.com
}

// zero parent
type EnvelopeResponse struct {
   Body Body
}

// one parent
type CertificateChains struct {
   CertificateChain Bytes
}

// zero parent
type Data struct {
   CertificateChains CertificateChains
   Features          Features
}

// one parent
type Feature struct {
   Name string `xml:",attr"`
}

// one parent
type Features struct {
   Feature Feature
}
