package playready

import (
   "bytes"
   "encoding/binary"
   "io"
)

// reader is a wrapper around bytes.Reader with helper methods.
type reader struct{ *bytes.Reader }

func newReader(data []byte) *reader {
   return &reader{bytes.NewReader(data)}
}

func (r *reader) ReadBytes(n int) ([]byte, error) {
   buf := make([]byte, n)
   _, err := io.ReadFull(r, buf)
   return buf, err
}

func (r *reader) ReadUint16() (uint16, error) {
   var val uint16
   err := binary.Read(r, binary.LittleEndian, &val)
   return val, err
}

func (r *reader) ReadUint32() (uint32, error) {
   var val uint32
   err := binary.Read(r, binary.LittleEndian, &val)
   return val, err
}

func (r *reader) ReadID() ([16]byte, error) {
   var id [16]byte
   _, err := io.ReadFull(r, id[:])
   return id, err
}

func (r *reader) ReadByteArray() ([]byte, error) {
   length, err := r.ReadUint32()
   if err != nil {
      return nil, err
   }
   return r.ReadBytes(int(length))
}

func (r *reader) ReadByteArray16() ([]byte, error) {
   length, err := r.ReadUint16()
   if err != nil {
      return nil, err
   }
   return r.ReadBytes(int(length))
}

func (r *reader) ReadDwordList() ([]uint32, error) {
   count, err := r.ReadUint32()
   if err != nil {
      return nil, err
   }
   dwords := make([]uint32, count)
   err = binary.Read(r, binary.LittleEndian, &dwords)
   if err != nil {
      return nil, err
   }
   return dwords, nil
}

// writer is a wrapper around bytes.Buffer with helper methods.
type writer struct{ *bytes.Buffer }

func newWriter() *writer {
   return &writer{new(bytes.Buffer)}
}

func (w *writer) WriteUint16(val uint16) error {
   return binary.Write(w, binary.LittleEndian, val)
}

func (w *writer) WriteUint32(val uint32) error {
   return binary.Write(w, binary.LittleEndian, val)
}

func (w *writer) WriteID(id [16]byte) error {
   _, err := w.Write(id[:])
   return err
}

func (w *writer) WriteByteArray(data []byte) error {
   if err := w.WriteUint32(uint32(len(data))); err != nil {
      return err
   }
   _, err := w.Write(data)
   return err
}

func (w *writer) WriteByteArray16(data []byte) error {
   if err := w.WriteUint16(uint16(len(data))); err != nil {
      return err
   }
   _, err := w.Write(data)
   return err
}

func (w *writer) WriteDwordList(data []uint32) error {
   if err := w.WriteUint32(uint32(len(data))); err != nil {
      return err
   }
   return binary.Write(w, binary.LittleEndian, data)
}
