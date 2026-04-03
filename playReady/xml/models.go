// xml/models.go
package xml

import (
   "encoding/base64"
   "encoding/xml"
)

var (
   Marshal   = xml.Marshal
   Unmarshal = xml.Unmarshal
)

type AcquireLicense struct {
   Challenge OuterChallenge `xml:"challenge"`  // microsoft.com
   XmlNs     string         `xml:"xmlns,attr"` // microsoft.com
}

type Body struct {
   AcquireLicense         *AcquireLicense // microsoft.com
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

type CertificateChains struct {
   CertificateChain Bytes // microsoft.com
}

type CipherData struct {
   CipherValue Bytes // microsoft.com
}

type ContentHeader struct {
   WrmHeader WrmHeader `xml:"WRMHEADER"` // microsoft.com
}

type CustomAttributes struct {
   ContentId string `xml:"CONTENTID"` // 9c9media.com
}

type Data struct {
   CertificateChains CertificateChains // microsoft.com
   Features          Features          // microsoft.com
}

type EncryptedData struct {
   CipherData       CipherData        // microsoft.com
   EncryptionMethod EncryptionMethod  // microsoft.com
   KeyInfo          EncryptedDataInfo // microsoft.com
   // ATTRIBUTE ORDER MATTERS
   XmlNs string `xml:"xmlns,attr"` // microsoft.com
   Type  string `xml:"Type,attr"`  // microsoft.com
}

type EncryptedDataInfo struct {
   EncryptedKey EncryptedKey // microsoft.com
   XmlNs        string       `xml:"xmlns,attr"` // microsoft.com
}

type EncryptedKey struct {
   CipherData       CipherData       // microsoft.com
   EncryptionMethod EncryptionMethod // microsoft.com
   KeyInfo          EncryptedKeyInfo // microsoft.com
   XmlNs            string           `xml:"xmlns,attr"` // microsoft.com
}

type EncryptedKeyInfo struct {
   KeyName string // microsoft.com
   XmlNs   string `xml:"xmlns,attr"` // microsoft.com
}

type EncryptionMethod struct {
   Algorithm string `xml:"Algorithm,attr"` // microsoft.com
}

type Envelope struct {
   Body    Body     `xml:"soap:Body"`       // microsoft.com
   Soap    string   `xml:"xmlns:soap,attr"` // microsoft.com
   XMLName xml.Name `xml:"soap:Envelope"`   // microsoft.com
}

type EnvelopeResponse struct {
   Body Body
}

type Feature struct {
   Name string `xml:",attr"` // microsoft.com
}

type Features struct {
   Feature Feature // microsoft.com
}

type InnerChallenge struct {
   La        *La       // microsoft.com
   Signature Signature // microsoft.com
   XmlNs     string    `xml:"xmlns,attr"` // microsoft.com
}

type La struct {
   ClientTime    int           // 9c9media.com
   ContentHeader ContentHeader // microsoft.com
   EncryptedData EncryptedData // microsoft.com
   LicenseNonce  Bytes         // 9c9media.com
   Version       string        // microsoft.com
   XMLName       xml.Name      `xml:"LA"` // microsoft.com
   // ATTRIBUTE ORDER MATTERS
   XmlNs string `xml:"xmlns,attr"` // microsoft.com
   Id    string `xml:"Id,attr"`    // microsoft.com
}

type OuterChallenge struct {
   Challenge InnerChallenge // microsoft.com
}

type ProtectInfo struct {
   AlgId  string `xml:"ALGID"`  // microsoft.com
   KeyLen int    `xml:"KEYLEN"` // microsoft.com
}

type Reference struct {
   DigestValue Bytes  // microsoft.com
   Uri         string `xml:"URI,attr"` // microsoft.com
}

type Signature struct {
   SignatureValue Bytes      // microsoft.com
   SignedInfo     SignedInfo // microsoft.com
}

type SignedInfo struct {
   Reference Reference // microsoft.com
   XmlNs     string    `xml:"xmlns,attr"` // microsoft.com
}

type WrmHeader struct {
   Data WrmHeaderData `xml:"DATA"` // microsoft.com
   // ATTRIBUTE ORDER MATTERS
   XmlNs   string `xml:"xmlns,attr"`   // microsoft.com
   Version string `xml:"version,attr"` // microsoft.com
}

type WrmHeaderData struct {
   CustomAttributes *CustomAttributes `xml:"CUSTOMATTRIBUTES"` // 9c9media.com
   Kid              Bytes             `xml:"KID"`              // microsoft.com
   ProtectInfo      ProtectInfo       `xml:"PROTECTINFO"`      // microsoft.com
}
