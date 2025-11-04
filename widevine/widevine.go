package widevine

import (
   "41.neocities.org/protobuf"
   "crypto"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "crypto/x509"
   "encoding/pem"
   "github.com/emmansun/gmsm/cbcmac"
   "iter"
)

func (c *Cdm) New(private_key, client_id, psshVar []byte) error {
   block, _ := pem.Decode(private_key)
   var err error
   c.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      // L1
      key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
      if err != nil {
         return err
      }
      c.private_key = key.(*rsa.PrivateKey)
   }
   c.license_request = protobuf.Message{ // LicenseRequest
      protobuf.Bytes(1, client_id), // ClientIdentification client_id
      protobuf.LenPrefix(2, // ContentIdentification content_id
         protobuf.LenPrefix(1, // WidevinePsshData widevine_pssh_data
            protobuf.Bytes(1, psshVar),
         ),
      ),
   }.Marshal()
   return nil
}

func (c *Cdm) Block(body ResponseBody) (cipher.Block, error) {
   session_key, err := rsa.DecryptOAEP(
      sha1.New(), nil, c.private_key, body.sessionKey(), nil,
   )
   if err != nil {
      return nil, err
   }
   var data []byte
   data = append(data, 1)
   data = append(data, "ENCRYPTION"...)
   data = append(data, 0)
   data = append(data, c.license_request...)
   data = append(data, 0, 0, 0, 128) // size
   block, err := aes.NewCipher(session_key)
   if err != nil {
      return nil, err
   }
   return aes.NewCipher(cbcmac.NewCMAC(block, aes.BlockSize).MAC(data))
}

func (c *Cdm) RequestBody() ([]byte, error) {
   hash := sha1.Sum(c.license_request)
   signature, err := rsa.SignPSS(
      fill{},
      c.private_key,
      crypto.SHA1,
      hash[:],
      &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash},
   )
   if err != nil {
      return nil, err
   }
   // SignedMessage
   signed := protobuf.Message{
      // kktv.me
      // type: LICENSE_REQUEST
      protobuf.Varint(1, 1),
      // LicenseRequest msg
      protobuf.Bytes(2, c.license_request),
      // bytes signature
      protobuf.Bytes(3, signature),
   }
   return signed.Marshal(), nil
}

func (k KeyContainer) Id() []byte {
   for field := range k[0].Get(1) {
      return field.Bytes
   }
   return nil
}

func (k KeyContainer) iv() []byte {
   for field := range k[0].Get(2) {
      return field.Bytes
   }
   return nil
}

func (k KeyContainer) Key(block cipher.Block) []byte {
   for f := range k[0].Get(3) {
      cipher.NewCBCDecrypter(block, k.iv()).CryptBlocks(f.Bytes, f.Bytes)
      return unpad(f.Bytes)
   }
   return nil
}

func unpad(data []byte) []byte {
   if len(data) >= 1 {
      pad := data[len(data)-1]
      if len(data) >= int(pad) {
         data = data[:len(data)-int(pad)]
      }
   }
   return data
}

type Cdm struct {
   license_request []byte
   private_key     *rsa.PrivateKey
}

type KeyContainer [1]protobuf.Message

func (r ResponseBody) Container() iter.Seq[KeyContainer] {
   return func(yield func(KeyContainer) bool) {
      for field := range r[0].Get(2) {
         for field := range field.Message.Get(3) {
            if !yield(KeyContainer{field.Message}) {
               return
            }
         }
      }
   }
}

func (r ResponseBody) sessionKey() []byte {
   for field := range r[0].Get(4) {
      return field.Bytes
   }
   return nil
}

func (p *Pssh) Marshal() []byte {
   var data protobuf.Message
   for _, key_id := range p.KeyIds {
      data = append(data, protobuf.Bytes(2, key_id))
   }
   if len(p.ContentId) >= 1 {
      data = append(data, protobuf.Bytes(4, p.ContentId))
   }
   return data.Marshal()
}

type Pssh struct {
   ContentId []byte
   KeyIds    [][]byte
}

func (r *ResponseBody) Unmarshal(data []byte) error {
   return r[0].Unmarshal(data)
}

// SignedMessage
// LICENSE = 2;
type ResponseBody [1]protobuf.Message

func (fill) Read(data []byte) (int, error) {
   return len(data), nil
}

type fill struct{}
