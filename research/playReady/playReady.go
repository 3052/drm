package playready

import (
   "fmt"
   "io"
)

// Parse decodes a PlayReady binary certificate chain or a single certificate
// from a byte slice into a structured Go representation.
func Parse(data []byte) (*Chain, error) {
   if len(data) < 4 {
      return nil, ErrBufferTooSmall
   }
   r := newReader(data)
   tag, err := r.ReadUint32()
   if err != nil {
      return nil, err
   }
   r.Seek(0, io.SeekStart) // Rewind

   chain := &Chain{RawData: data}

   switch tag {
   case ChainHeaderTag:
      if err := parseChain(chain); err != nil {
         return nil, err
      }
      return chain, nil
   case CertHeaderTag:
      // Handle a single certificate by wrapping it in a Chain struct.
      cert := &Cert{RawData: data}
      if err := parseCert(cert); err != nil {
         return nil, err
      }
      chain.Header = &ChainExtendedHeader{
         Version: cert.Header.Version,
         Length:  uint32(len(data)),
         Flags:   0,
         Certs:   1,
      }
      chain.Certificates = []*Cert{cert}
      return chain, nil
   default:
      return nil, fmt.Errorf("tag 0x%X: %w", tag, ErrInvalidChainHeader)
   }
}
