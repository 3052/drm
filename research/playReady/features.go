package bcert

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func parseFeatureInfo(data []byte) (*FeatureInformation, error) {
	if len(data) < 4 {
		return nil, errors.New("feature info data too short")
	}

	info := &FeatureInformation{}
	featureCount := binary.LittleEndian.Uint32(data[0:])

	if featureCount > maxAllocationSize/4 {
		return nil, errors.New("feature count too large")
	}

	if len(data) >= 8 {
		info.FeatureSet = binary.LittleEndian.Uint32(data[4:])
	}

	if featureCount > 0 && len(data) >= 8 {
		offset := 8
		info.Features = make([]uint32, featureCount)
		for i := uint32(0); i < featureCount && offset+4 <= len(data); i++ {
			info.Features[i] = binary.LittleEndian.Uint32(data[offset:])
			offset += 4
		}
	}

	return info, nil
}

func serializeFeatureInfo(buf *bytes.Buffer, info *FeatureInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeFeature, FlagMustUnderstand)
	if err != nil {
		return err
	}

	binary.Write(buf, binary.LittleEndian, uint32(len(info.Features)))
	binary.Write(buf, binary.LittleEndian, info.FeatureSet)

	for _, feature := range info.Features {
		binary.Write(buf, binary.LittleEndian, feature)
	}

	updateObjLength(buf, lengthPos, objStart)
	return nil
}

func parseKeyInfo(data []byte) (*KeyInformation, error) {
	if len(data) < 4 {
		return nil, errors.New("key info data too short")
	}

	info := &KeyInformation{}
	info.Entries = binary.LittleEndian.Uint32(data[0:])
	offset := 4

	if info.Entries > 100 {
		return nil, errors.New("too many key entries")
	}

	if info.Entries > 0 {
		info.KeyTypes = make([]KeyType, info.Entries)

		for i := uint32(0); i < info.Entries; i++ {
			if offset+8 > len(data) {
				return nil, errors.New("key entry incomplete")
			}

			kt := &info.KeyTypes[i]
			kt.Type = binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			kt.KeyLength = binary.LittleEndian.Uint16(data[offset:])
			offset += 2

			keyValueLen := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			if keyValueLen > maxAllocationSize {
				return nil, errors.New("key value too large")
			}

			if keyValueLen > 0 && offset+int(keyValueLen) <= len(data) {
				kt.KeyValue = make([]byte, keyValueLen)
				copy(kt.KeyValue, data[offset:offset+int(keyValueLen)])
				offset += int(keyValueLen)
			}

			if offset+4 > len(data) {
				return nil, errors.New("key usage count incomplete")
			}

			usageCount := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			if usageCount > 1000 {
				return nil, errors.New("too many key usages")
			}

			if usageCount > 0 {
				kt.KeyUsages = make([]uint32, usageCount)
				for j := uint32(0); j < usageCount && offset+4 <= len(data); j++ {
					kt.KeyUsages[j] = binary.LittleEndian.Uint32(data[offset:])
					offset += 4
				}
			}
		}
	}

	return info, nil
}

func serializeKeyInfo(buf *bytes.Buffer, info *KeyInformation) error {
	objStart := buf.Len()
	lengthPos, err := writeObjHeader(buf, ObjTypeKey, FlagMustUnderstand)
	if err != nil {
		return err
	}

	binary.Write(buf, binary.LittleEndian, info.Entries)

	for i := uint32(0); i < info.Entries; i++ {
		kt := &info.KeyTypes[i]
		binary.Write(buf, binary.LittleEndian, kt.Type)
		binary.Write(buf, binary.LittleEndian, kt.KeyLength)
		binary.Write(buf, binary.LittleEndian, uint32(len(kt.KeyValue)))
		if len(kt.KeyValue) > 0 {
			buf.Write(kt.KeyValue)
		}

		binary.Write(buf, binary.LittleEndian, uint32(len(kt.KeyUsages)))
		for _, usage := range kt.KeyUsages {
			binary.Write(buf, binary.LittleEndian, usage)
		}
	}

	updateObjLength(buf, lengthPos, objStart)
	return nil
}
