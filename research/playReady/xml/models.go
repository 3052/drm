// xml/models.go
package xml

import (
   "encoding/base64"
   "encoding/xml"
)

const Header = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"

var (
   Marshal   = xml.Marshal
   Unmarshal = xml.Unmarshal
)

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

///

type WrmHeaderData struct {
   ProtectInfo      ProtectInfo       `xml:"PROTECTINFO"`
   Kid              Bytes             `xml:"KID"`
   LaUrl            string            `xml:"LA_URL,omitempty"`
   Checksum         Bytes             `xml:"CHECKSUM,omitempty"`
   CustomAttributes *CustomAttributes `xml:"CUSTOMATTRIBUTES,omitempty"`
}

type CustomAttributes struct {
   ContentID string `xml:"CONTENTID,omitempty"`
}

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

type Envelope struct {
   XMLName xml.Name `xml:"soap:Envelope"`
   Xsi     string   `xml:"xmlns:xsi,attr"`
   Xsd     string   `xml:"xmlns:xsd,attr"`
   Soap    string   `xml:"xmlns:soap,attr"`
   Body    Body     `xml:"soap:Body"`
}

type EnvelopeResponse struct {
   Body Body
}

type Signature struct {
   XmlNs          string            `xml:"xmlns,attr,omitempty"`
   SignedInfo     SignedInfo
   SignatureValue Bytes
   KeyInfo        *SignatureKeyInfo `xml:"KeyInfo,omitempty"`
}

type SignatureKeyInfo struct {
   XmlNs    string   `xml:"xmlns,attr"`
   KeyValue KeyValue `xml:"KeyValue"`
}

type KeyValue struct {
   ECCKeyValue ECCKeyValue `xml:"ECCKeyValue"`
}

type ECCKeyValue struct {
   PublicKey Bytes `xml:"PublicKey"`
}

type Reference struct {
   Uri          string `xml:"URI,attr"`
   DigestMethod Algorithm
   DigestValue  Bytes
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
   XmlNs            string           `xml:"xmlns,attr"`
   EncryptionMethod Algorithm
   KeyInfo          EncryptedKeyInfo
   CipherData       CipherData
}

type EncryptedKeyInfo struct {
   XmlNs   string `xml:"xmlns,attr"`
   KeyName string
}

type Feature struct {
   Name string `xml:",attr"`
}

type Features struct {
   Feature Feature
}

type InnerChallenge struct {
   XmlNs     string `xml:"xmlns,attr"`
   La        *La
   Signature Signature
}

type KeyInfo struct {
   XmlNs        string `xml:"xmlns,attr"`
   EncryptedKey EncryptedKey
}

type ClientInfo struct {
   ClientVersion string `xml:"CLIENTVERSION"`
}

type La struct {
   XMLName       xml.Name `xml:"LA"`
   XmlNs         string   `xml:"xmlns,attr"`
   Id            string   `xml:"Id,attr"`
   XmlSpace      string   `xml:"xml:space,attr"`
   Version       string
   ContentHeader ContentHeader
   ClientInfo    *ClientInfo `xml:"CLIENTINFO,omitempty"`
   LicenseNonce  string      `xml:"LicenseNonce,omitempty"`
   ClientTime    string      `xml:"ClientTime,omitempty"`
   EncryptedData EncryptedData
}

type ProtectInfo struct {
   KeyLen string `xml:"KEYLEN"`
   AlgId  string `xml:"ALGID"`
}

type SignedInfo struct {
   XmlNs                  string `xml:"xmlns,attr"`
   CanonicalizationMethod Algorithm
   SignatureMethod        Algorithm
   Reference              Reference
}

type WrmHeader struct {
   XmlNs   string        `xml:"xmlns,attr"`
   Version string        `xml:"version,attr"`
   Data    WrmHeaderData `xml:"DATA"`
}
