package bcert

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func parseSignatureInfo(data []byte) (*SignatureInformation, error) {
	if len(data) < 6 {
		return nil, errors.New("signature info too short")
	}

	info := &SignatureInformation{}
	info.SignatureType = binary.LittleEndian.Uint16(data[0:])

	sigLen := binary.LittleEndian.Uint32(data[2:])
	offset := 6

	if sigLen > 0 && offset+int(sigLen) <= len(data) {
		info.Signature = make([]byte, sigLen)
		copy(info.Signature, data[offset:offset+int(sigLen)])
		offset += int(sigLen)
	}

	if offset+4 > len(data) {
		return info, nil
	}

	keyLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if keyLen > 0 && offset+int(keyLen) <= len(data) {
		info.IssuerKey = make([]byte, keyLen)
		copy(info.IssuerKey, data[offset:offset+int(keyLen)])
	}

	return info, nil
}

func serializeSignatureInfo(buf *bytes.Buffer, info *SignatureInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeSignature, 0)
	if err != nil {
		return err
	}

	binary.Write(buf, binary.LittleEndian, info.SignatureType)
	binary.Write(buf, binary.LittleEndian, uint32(len(info.Signature)))
	buf.Write(info.Signature)
	binary.Write(buf, binary.LittleEndian, uint32(len(info.IssuerKey)))
	buf.Write(info.IssuerKey)

	updateObjLength(buf, lengthPos, objStart)
	return nil
}
