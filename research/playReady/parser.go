package bcert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
)

func ParseCertificate(data []byte) (*Certificate, error) {
	log.Printf("ParseCertificate: data length = %d", len(data))
	log.Printf("First 32 bytes: %x", data[:min(32, len(data))])

	if len(data) < 16 {
		return nil, errors.New("certificate data too short")
	}

	cert := &Certificate{}
	offset := 0

	tag := binary.BigEndian.Uint32(data[offset:])
	log.Printf("Tag at offset %d: 0x%08X", offset, tag)

	if tag == TagCERT {
		log.Printf("Found CERT tag, skipping")
		offset += 4
		cert.Version = binary.BigEndian.Uint32(data[offset:])
		log.Printf("Version at offset %d: %d", offset, cert.Version)
		offset += 4
		cert.CbCert = binary.BigEndian.Uint32(data[offset:])
		log.Printf("Length at offset %d: %d", offset, cert.CbCert)
		offset += 4
		cert.SignedLength = binary.BigEndian.Uint32(data[offset:])
		log.Printf("SignedLength at offset %d: %d", offset, cert.SignedLength)
		offset += 4
	}

	signedEnd := offset + int(cert.SignedLength)

	for offset < len(data) {
		if offset+8 > len(data) {
			break
		}

		objType := binary.BigEndian.Uint16(data[offset:])
		flags := binary.BigEndian.Uint16(data[offset+2:])
		objLength := binary.BigEndian.Uint32(data[offset+4:])

		log.Printf("Object at offset %d: type=0x%04X, length=%d", offset, objType, objLength)

		dataStart := offset + 8
		dataEnd := offset + int(objLength)

		if dataEnd > len(data) {
			return nil, fmt.Errorf("object extends beyond data: %d > %d", dataEnd, len(data))
		}

		objData := data[dataStart:dataEnd]

		var err error
		switch objType {
		case ObjTypeBasic:
			cert.BasicInformation, err = parseBasicInfo(objData)
		case ObjTypeFeature:
			cert.FeatureInformation, err = parseFeatureInfo(objData)
		case ObjTypeKey:
			cert.KeyInformation, err = parseKeyInfo(objData)
		case ObjTypeSignature:
			cert.SignatureInformation, err = parseSignatureInfo(objData)
		case ObjTypeDomain:
			cert.DomainInformation, err = parseDomainInfo(objData)
		case ObjTypeDevice:
			cert.DeviceInformation, err = parseDeviceInfo(objData)
		case ObjTypePC:
			cert.PCInfo, err = parsePCInfo(objData)
		case ObjTypeManufacturer:
			cert.ManufacturerInfo, err = parseManufacturerInfo(objData)
		case ObjTypeSilverlight:
			cert.SilverlightInfo, err = parseSilverlightInfo(objData)
		case ObjTypeMetering:
			cert.MeteringInfo, err = parseMeteringInfo(objData)
		case ObjTypeExtDataSigKey:
			cert.ExtDataSigKeyInfo, err = parseExtDataSigKeyInfo(objData)
		case ObjTypeExtDataContainer:
			cert.ExtDataContainer, err = parseExtDataContainer(objData)
		case ObjTypeServerType:
			cert.ServerTypeInfo, err = parseServerTypeInfo(objData)
		case ObjTypeSecurityVersion:
			cert.SecurityVersion, err = parseSecurityVersion(objData)
		case ObjTypeSecurityVersion2:
			cert.SecurityVersion2, err = parseSecurityVersion(objData)
		default:
			log.Printf("Unknown object type 0x%04X at offset %d (flags=0x%04X)", objType, offset, flags)
			if flags&FlagMustUnderstand != 0 {
				return nil, fmt.Errorf("unknown must-understand object type 0x%04X", objType)
			}
		}

		if err != nil {
			return nil, fmt.Errorf("parsing object type 0x%04X: %w", objType, err)
		}

		offset = dataEnd

		if offset >= signedEnd && cert.SignatureInformation != nil {
			break
		}
	}

	return cert, nil
}

func ParseCertificateChain(data []byte) (*CertificateChain, error) {
	log.Printf("ParseCertificateChain: data length = %d", len(data))
	log.Printf("First 32 bytes: %x", data[:min(32, len(data))])

	if len(data) < 20 {
		return nil, errors.New("chain data too short")
	}

	tag := binary.BigEndian.Uint32(data[0:])
	log.Printf("Tag at offset 0: 0x%08X", tag)

	if tag != TagCHAI {
		log.Printf("Not a chain, trying as single certificate")
		cert, err := ParseCertificate(data)
		if err != nil {
			return nil, err
		}
		serialized, err := cert.Serialize()
		if err != nil {
			return nil, err
		}
		return &CertificateChain{
			Header: ChainHeader{
				Version: 1,
				CbChain: uint32(len(serialized) + 20),
				Flags:   0,
				Certs:   1,
			},
			CertHeaders: []CertificateHeader{
				{
					Version:      cert.Version,
					CbCert:       cert.CbCert,
					SignedLength: cert.SignedLength,
					RawData:      serialized,
				},
			},
		}, nil
	}

	log.Printf("Found CHAI tag - parsing as chain")

	chain := &CertificateChain{}
	chain.Header.Version = binary.BigEndian.Uint32(data[4:])
	chain.Header.CbChain = binary.BigEndian.Uint32(data[8:])
	chain.Header.Flags = binary.BigEndian.Uint32(data[12:])
	chain.Header.Certs = binary.BigEndian.Uint32(data[16:])

	log.Printf("Chain header: version=%d, cbChain=%d, flags=0x%08X, certs=%d",
		chain.Header.Version, chain.Header.CbChain, chain.Header.Flags, chain.Header.Certs)

	offset := 20
	chain.CertHeaders = make([]CertificateHeader, chain.Header.Certs)

	for i := uint32(0); i < chain.Header.Certs; i++ {
		if offset+16 > len(data) {
			return nil, fmt.Errorf("certificate %d: header truncated", i)
		}

		log.Printf("Parsing certificate %d at offset %d", i, offset)

		certTag := binary.BigEndian.Uint32(data[offset:])
		if certTag != TagCERT {
			return nil, fmt.Errorf("certificate %d: invalid tag 0x%08X", i, certTag)
		}
		log.Printf("Found CERT tag at offset %d", offset)

		certHeader := &chain.CertHeaders[i]
		certHeader.Version = binary.BigEndian.Uint32(data[offset+4:])
		certHeader.CbCert = binary.BigEndian.Uint32(data[offset+8:])
		certHeader.SignedLength = binary.BigEndian.Uint32(data[offset+12:])

		log.Printf("Certificate %d: version=%d, length=%d, signedLength=%d",
			i, certHeader.Version, certHeader.CbCert, certHeader.SignedLength)

		certEnd := offset + int(certHeader.CbCert)
		if certEnd > len(data) {
			return nil, fmt.Errorf("certificate %d: extends beyond data", i)
		}

		certHeader.RawData = make([]byte, certHeader.CbCert)
		copy(certHeader.RawData, data[offset:certEnd])

		offset = certEnd
	}

	return chain, nil
}

func (chain *CertificateChain) GetCertificate(index uint32) (*Certificate, error) {
	if index >= chain.Header.Certs {
		return nil, errors.New("certificate index out of range")
	}
	return ParseCertificate(chain.CertHeaders[index].RawData)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
