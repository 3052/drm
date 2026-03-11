package playReady

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/xml"
	"errors"
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

func (e *Envelope) Marshal() ([]byte, error) {
	return xml.Marshal(e)
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

func (d *Data) Marshal() ([]byte, error) {
	return xml.Marshal(d)
}

func (l *La) Marshal() ([]byte, error) {
	return xml.Marshal(l)
}

func (s *SignedInfo) Marshal() ([]byte, error) {
	return xml.Marshal(s)
}

func newLa(m *ecdsa.PublicKey, cipherData, kid []byte) La {
	return La{
		XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/protocols",
		Id:      "SignedData",
		Version: "1",
		ContentHeader: ContentHeader{
			WrmHeader: WrmHeader{
				XmlNs:   "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader",
				Version: "4.0.0.0",
				Data: WrmHeaderData{
					ProtectInfo: ProtectInfo{
						KeyLen: "16",
						AlgId:  "AESCTR",
					},
					Kid: kid,
				},
			},
		},
		EncryptedData: EncryptedData{
			XmlNs: "http://www.w3.org/2001/04/xmlenc#",
			Type:  "http://www.w3.org/2001/04/xmlenc#Element",
			EncryptionMethod: Algorithm{
				Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
			},
			KeyInfo: KeyInfo{
				XmlNs: "http://www.w3.org/2000/09/xmldsig#",
				EncryptedKey: EncryptedKey{
					XmlNs: "http://www.w3.org/2001/04/xmlenc#",
					EncryptionMethod: Algorithm{
						Algorithm: "http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256",
					},
					KeyInfo: EncryptedKeyInfo{
						XmlNs:   "http://www.w3.org/2000/09/xmldsig#",
						KeyName: "WMRMServer",
					},
					CipherData: CipherData{
						CipherValue: elGamalEncrypt(m, elGamalKeyGeneration()),
					},
				},
			},
			CipherData: CipherData{
				CipherValue: cipherData,
			},
		},
	}
}
