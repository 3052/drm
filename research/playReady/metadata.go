package bcert

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func parseDomainInfo(data []byte) (*DomainInformation, error) {
	if len(data) < 36 {
		return nil, errors.New("domain info too short")
	}

	info := &DomainInformation{}
	copy(info.ServiceID[:], data[0:16])
	copy(info.AccountID[:], data[16:32])
	info.Revision = binary.LittleEndian.Uint32(data[32:])

	urlLen := binary.LittleEndian.Uint32(data[36:])
	if urlLen > 0 && len(data) >= 40+int(urlLen) {
		info.DomainURL = make([]byte, urlLen)
		copy(info.DomainURL, data[40:40+urlLen])
	}

	return info, nil
}

func serializeDomainInfo(buf *bytes.Buffer, info *DomainInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeDomain, FlagMustUnderstand)
	if err != nil {
		return err
	}

	buf.Write(info.ServiceID[:])
	buf.Write(info.AccountID[:])
	binary.Write(buf, binary.LittleEndian, info.Revision)
	binary.Write(buf, binary.LittleEndian, uint32(len(info.DomainURL)))
	buf.Write(info.DomainURL)

	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parsePCInfo(data []byte) (*PCInfo, error) {
	if len(data) < 4 {
		return nil, errors.New("pc info too short")
	}

	return &PCInfo{
		SecurityVersion: binary.LittleEndian.Uint32(data[0:]),
	}, nil
}

func serializePCInfo(buf *bytes.Buffer, info *PCInfo) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypePC, FlagMustUnderstand)
	if err != nil {
		return err
	}

	binary.Write(buf, binary.LittleEndian, info.SecurityVersion)

	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parseDeviceInfo(data []byte) (*DeviceInformation, error) {
	if len(data) < 64 {
		return nil, errors.New("device info too short")
	}

	info := &DeviceInformation{}
	copy(info.ManufacturerKey[:], data[0:64])
	return info, nil
}

func serializeDeviceInfo(buf *bytes.Buffer, info *DeviceInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeDevice, FlagMustUnderstand)
	if err != nil {
		return err
	}

	buf.Write(info.ManufacturerKey[:])

	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parseManufacturerInfo(data []byte) (*ManufacturerInformation, error) {
	if len(data) < 12 {
		return nil, errors.New("manufacturer info too short")
	}

	info := &ManufacturerInformation{}
	offset := 0

	nameLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if nameLen > 0 && offset+int(nameLen) <= len(data) {
		info.ManufacturerName = make([]byte, nameLen)
		copy(info.ManufacturerName, data[offset:offset+int(nameLen)])
		offset += int(nameLen)
	}

	if offset+4 > len(data) {
		return info, nil
	}
	modelLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if modelLen > 0 && offset+int(modelLen) <= len(data) {
		info.ModelName = make([]byte, modelLen)
		copy(info.ModelName, data[offset:offset+int(modelLen)])
		offset += int(modelLen)
	}

	if offset+4 > len(data) {
		return info, nil
	}
	numberLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	if numberLen > 0 && offset+int(numberLen) <= len(data) {
		info.ModelNumber = make([]byte, numberLen)
		copy(info.ModelNumber, data[offset:offset+int(numberLen)])
	}

	return info, nil
}

func serializeManufacturerInfo(buf *bytes.Buffer, info *ManufacturerInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeManufacturer, FlagMustUnderstand)
	if err != nil {
		return err
	}

	binary.Write(buf, binary.LittleEndian, uint32(len(info.ManufacturerName)))
	buf.Write(info.ManufacturerName)
	binary.Write(buf, binary.LittleEndian, uint32(len(info.ModelName)))
	buf.Write(info.ModelName)
	binary.Write(buf, binary.LittleEndian, uint32(len(info.ModelNumber)))
	buf.Write(info.ModelNumber)

	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parseSilverlightInfo(data []byte) (*SilverlightInformation, error) {
	info := &SilverlightInformation{
		Data: make([]byte, len(data)),
	}
	copy(info.Data, data)
	return info, nil
}

func serializeSilverlightInfo(buf *bytes.Buffer, info *SilverlightInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeSilverlight, FlagMustUnderstand)
	if err != nil {
		return err
	}
	buf.Write(info.Data)
	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parseMeteringInfo(data []byte) (*MeteringInformation, error) {
	info := &MeteringInformation{
		Data: make([]byte, len(data)),
	}
	copy(info.Data, data)
	return info, nil
}

func serializeMeteringInfo(buf *bytes.Buffer, info *MeteringInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeMetering, FlagMustUnderstand)
	if err != nil {
		return err
	}
	buf.Write(info.Data)
	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parseExtDataSigKeyInfo(data []byte) (*ExtDataSigKeyInfo, error) {
	if len(data) < 8 {
		return nil, errors.New("ext data sig key info too short")
	}

	info := &ExtDataSigKeyInfo{}
	info.KeyType = binary.LittleEndian.Uint16(data[0:])
	info.KeyLength = binary.LittleEndian.Uint16(data[2:])

	keyLen := binary.LittleEndian.Uint32(data[4:])
	if keyLen > 0 && len(data) >= 8+int(keyLen) {
		info.PublicKey = make([]byte, keyLen)
		copy(info.PublicKey, data[8:8+keyLen])
	}

	return info, nil
}

func serializeExtDataSigKeyInfo(buf *bytes.Buffer, info *ExtDataSigKeyInfo) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeExtDataSigKey, FlagMustUnderstand)
	if err != nil {
		return err
	}

	binary.Write(buf, binary.LittleEndian, info.KeyType)
	binary.Write(buf, binary.LittleEndian, info.KeyLength)
	binary.Write(buf, binary.LittleEndian, uint32(len(info.PublicKey)))
	buf.Write(info.PublicKey)

	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parseExtDataContainer(data []byte) (*ExtDataContainer, error) {
	if len(data) < 4 {
		return nil, errors.New("ext data container too short")
	}

	container := &ExtDataContainer{}
	entryCount := binary.LittleEndian.Uint32(data[0:])
	offset := 4

	if entryCount > 100 {
		return nil, errors.New("too many ext data entries")
	}

	container.Entries = make([]ExtDataEntry, entryCount)

	for i := uint32(0); i < entryCount; i++ {
		if offset+8 > len(data) {
			break
		}

		entry := &container.Entries[i]
		entry.Type = binary.LittleEndian.Uint32(data[offset:])
		offset += 4

		dataLen := binary.LittleEndian.Uint32(data[offset:])
		offset += 4

		if dataLen > 0 && offset+int(dataLen) <= len(data) {
			entry.Data = make([]byte, dataLen)
			copy(entry.Data, data[offset:offset+int(dataLen)])
			offset += int(dataLen)
		}
	}

	return container, nil
}

func serializeExtDataContainer(buf *bytes.Buffer, container *ExtDataContainer) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeExtDataContainer, FlagMustUnderstand)
	if err != nil {
		return err
	}

	binary.Write(buf, binary.LittleEndian, uint32(len(container.Entries)))

	for _, entry := range container.Entries {
		binary.Write(buf, binary.LittleEndian, entry.Type)
		binary.Write(buf, binary.LittleEndian, uint32(len(entry.Data)))
		buf.Write(entry.Data)
	}

	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parseServerTypeInfo(data []byte) (*ServerTypeInformation, error) {
	if len(data) < 4 {
		return nil, errors.New("server type info too short")
	}

	return &ServerTypeInformation{
		SecurityVersion: binary.LittleEndian.Uint32(data[0:]),
	}, nil
}

func serializeServerTypeInfo(buf *bytes.Buffer, info *ServerTypeInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeServerType, FlagMustUnderstand)
	if err != nil {
		return err
	}

	binary.Write(buf, binary.LittleEndian, info.SecurityVersion)

	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parseSecurityVersion(data []byte) (*SecurityVersion, error) {
	if len(data) < 8 {
		return nil, errors.New("security version too short")
	}

	return &SecurityVersion{
		MinimumSecurityLevel: binary.LittleEndian.Uint32(data[0:]),
		MaximumSecurityLevel: binary.LittleEndian.Uint32(data[4:]),
	}, nil
}

func serializeSecurityVersion(buf *bytes.Buffer, info *SecurityVersion, objType uint16) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, objType, FlagMustUnderstand)
	if err != nil {
		return err
	}

	binary.Write(buf, binary.LittleEndian, info.MinimumSecurityLevel)
	binary.Write(buf, binary.LittleEndian, info.MaximumSecurityLevel)

	updateObjLength(buf, lengthPos, objStart)
	return nil
}
