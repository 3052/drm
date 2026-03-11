package playReady

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"github.com/deatil/go-cryptobin/mac"
)

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

func (l *license) decrypt(encrypt EcKey, data []byte) error {
	var envelope EnvelopeResponse
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
