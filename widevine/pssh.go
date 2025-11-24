package widevine

import "41.neocities.org/protobuf"

// WidevinePsshData represents the Widevine-specific protobuf message.
type WidevinePsshData struct {
	KeyIDs    [][]byte
	ContentID []byte
}

// Marshal serializes the WidevinePsshData struct into the protobuf wire format.
func (w *WidevinePsshData) Marshal() ([]byte, error) {
	var message protobuf.Message

	// Field 2: KeyIDs (Repeated)
	for _, keyID := range w.KeyIDs {
		if len(keyID) > 0 {
			message = append(message, protobuf.Bytes(2, keyID))
		}
	}

	// Field 4: ContentID (Optional)
	if len(w.ContentID) > 0 {
		message = append(message, protobuf.Bytes(4, w.ContentID))
	}

	return message.Encode()
}

// Unmarshal parses the protobuf wire format into the WidevinePsshData struct.
func (w *WidevinePsshData) Unmarshal(data []byte) error {
	var message protobuf.Message
	if err := message.Parse(data); err != nil {
		return err
	}

	// Reset fields
	w.KeyIDs = nil
	w.ContentID = nil

	// Field 2: KeyIDs
	it := message.Iterator(2)
	for it.Next() {
		if field := it.Field(); field != nil {
			w.KeyIDs = append(w.KeyIDs, field.Bytes)
		}
	}

	// Field 4: ContentID
	if field, found := message.Field(4); found {
		w.ContentID = field.Bytes
	}

	return nil
}
