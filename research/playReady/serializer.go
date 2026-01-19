package bcert

import (
	"bytes"
	"encoding/binary"
)

func (chain *CertificateChain) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(TagCHAI))
	binary.Write(buf, binary.LittleEndian, chain.Header.Version)
	cbChainPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, chain.Header.Flags)
	binary.Write(buf, binary.LittleEndian, chain.Header.Certs)

	for i := uint32(0); i < uint32(len(chain.CertHeaders)); i++ {
		buf.Write(chain.CertHeaders[i].RawData)
	}

	cbChain := uint32(buf.Len())
	binary.LittleEndian.PutUint32(buf.Bytes()[cbChainPos:], cbChain)
	return buf.Bytes(), nil
}

func (cert *Certificate) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(TagCERT))
	binary.Write(buf, binary.LittleEndian, cert.Version)
	cbCertPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint32(0))
	signedLengthPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint32(0))
	signedStart := buf.Len()

	if cert.BasicInformation != nil {
		if err := serializeBasicInfo(buf, cert.BasicInformation); err != nil {
			return nil, err
		}
	}
	if cert.FeatureInformation != nil {
		if err := serializeFeatureInfo(buf, cert.FeatureInformation); err != nil {
			return nil, err
		}
	}
	if cert.KeyInformation != nil {
		if err := serializeKeyInfo(buf, cert.KeyInformation); err != nil {
			return nil, err
		}
	}
	if cert.DomainInformation != nil {
		if err := serializeDomainInfo(buf, cert.DomainInformation); err != nil {
			return nil, err
		}
	}
	if cert.DeviceInformation != nil {
		if err := serializeDeviceInfo(buf, cert.DeviceInformation); err != nil {
			return nil, err
		}
	}
	if cert.PCInfo != nil {
		if err := serializePCInfo(buf, cert.PCInfo); err != nil {
			return nil, err
		}
	}
	if cert.ManufacturerInfo != nil {
		if err := serializeManufacturerInfo(buf, cert.ManufacturerInfo); err != nil {
			return nil, err
		}
	}
	if cert.SilverlightInfo != nil {
		if err := serializeSilverlightInfo(buf, cert.SilverlightInfo); err != nil {
			return nil, err
		}
	}
	if cert.MeteringInfo != nil {
		if err := serializeMeteringInfo(buf, cert.MeteringInfo); err != nil {
			return nil, err
		}
	}
	if cert.ExtDataSigKeyInfo != nil {
		if err := serializeExtDataSigKeyInfo(buf, cert.ExtDataSigKeyInfo); err != nil {
			return nil, err
		}
	}
	if cert.ExtDataContainer != nil {
		if err := serializeExtDataContainer(buf, cert.ExtDataContainer); err != nil {
			return nil, err
		}
	}
	if cert.ServerTypeInfo != nil {
		if err := serializeServerTypeInfo(buf, cert.ServerTypeInfo); err != nil {
			return nil, err
		}
	}
	if cert.SecurityVersion != nil {
		if err := serializeSecurityVersion(buf, cert.SecurityVersion, ObjTypeSecurityVersion); err != nil {
			return nil, err
		}
	}
	if cert.SecurityVersion2 != nil {
		if err := serializeSecurityVersion(buf, cert.SecurityVersion2, ObjTypeSecurityVersion2); err != nil {
			return nil, err
		}
	}

	signedEnd := buf.Len()
	signedLength := uint32(signedEnd - signedStart)
	binary.LittleEndian.PutUint32(buf.Bytes()[signedLengthPos:], signedLength)

	if cert.SignatureInformation != nil {
		if err := serializeSignatureInfo(buf, cert.SignatureInformation); err != nil {
			return nil, err
		}
	}

	cbCert := uint32(buf.Len())
	binary.LittleEndian.PutUint32(buf.Bytes()[cbCertPos:], cbCert)
	return buf.Bytes(), nil
}

func writeObjHeader(buf *bytes.Buffer, objType uint16, flags uint16) (int, error) {
	binary.Write(buf, binary.LittleEndian, objType)
	binary.Write(buf, binary.LittleEndian, flags)
	lengthPos := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return lengthPos, nil
}

func updateObjLength(buf *bytes.Buffer, lengthPos int, objStart int) {
	objLength := uint32(buf.Len() - objStart)
	binary.LittleEndian.PutUint32(buf.Bytes()[lengthPos:], objLength)
}
