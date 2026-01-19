package bcert

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func parseBasicInfo(data []byte) (*BasicInformation, error) {
	if len(data) < 76 {
		return nil, errors.New("basic info data too short")
	}

	info := &BasicInformation{}
	copy(info.CertID[:], data[0:16])
	info.SecurityLevel = binary.LittleEndian.Uint32(data[16:])
	info.Type = binary.LittleEndian.Uint32(data[20:])
	info.Flags = binary.LittleEndian.Uint32(data[24:])

	digestSize := binary.LittleEndian.Uint32(data[28:])
	if digestSize > 0 && len(data) >= 32+int(digestSize) {
		info.DigestValue = make([]byte, digestSize)
		copy(info.DigestValue, data[32:32+digestSize])
	}

	offset := 32 + int(digestSize)
	if offset+4 <= len(data) {
		info.ExpirationDate = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
	}

	if offset+16 <= len(data) {
		copy(info.ClientID[:], data[offset:offset+16])
	}

	return info, nil
}

func serializeBasicInfo(buf *bytes.Buffer, info *BasicInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeBasic, FlagMustUnderstand)
	if err != nil {
		return err
	}

	buf.Write(info.CertID[:])
	binary.Write(buf, binary.LittleEndian, info.SecurityLevel)
	binary.Write(buf, binary.LittleEndian, info.Type)
	binary.Write(buf, binary.LittleEndian, info.Flags)
	binary.Write(buf, binary.LittleEndian, uint32(len(info.DigestValue)))
	buf.Write(info.DigestValue)
	binary.Write(buf, binary.LittleEndian, info.ExpirationDate)
	buf.Write(info.ClientID[:])

	updateObjLength(buf, lengthPos, objStart)
	return nil
}
