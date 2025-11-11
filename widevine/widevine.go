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
   "errors"
   "github.com/emmansun/gmsm/cbcmac"
   "github.com/emmansun/gmsm/padding"
   "iter"
)

func (k KeyContainer) Key(block cipher.Block) ([]byte, error) {
   field, ok := k[0].Field(3) // bytes key
   if !ok {
      return nil, errors.New(".Field(3)")
   }
   cipher.NewCBCDecrypter(block, k.iv()).CryptBlocks(field.Bytes, field.Bytes)
   return padding.NewPKCS7Padding(aes.BlockSize).Unpad(field.Bytes)
}

func (k KeyContainer) iv() []byte {
   field, _ := k[0].Field(2)
   return field.Bytes
}

func (k KeyContainer) Id() []byte {
   field, ok := k[0].Field(1)
   if !ok {
      return nil
   }
   return field.Bytes
}

func (r ResponseBody) Container() iter.Seq[KeyContainer] {
   return func(yield func(KeyContainer) bool) {
      license, ok := r[0].Field(2) // License msg
      if ok {
         container := license.Message.Iterator(3) // KeyContainer key
         for container.Next() {
            field := container.Field()
            if !yield(KeyContainer{field.Message}) {
               return
            }
         }
      }
   }
}

func (r ResponseBody) sessionKey() []byte {
   field, _ := r[0].Field(4)
   return field.Bytes
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
      protobuf.NewVarint(1, 1),
      // LicenseRequest msg
      protobuf.NewBytes(2, c.license_request),
      // bytes signature
      protobuf.NewBytes(3, signature),
   }
   return signed.Encode()
}

func (c *Cdm) New(private_key, client_id, psshData []byte) error {
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
   c.license_request, err = protobuf.Message{ // LicenseRequest
      protobuf.NewBytes(1, client_id), // ClientIdentification client_id
      protobuf.NewMessage(2, // ContentIdentification content_id
         protobuf.NewMessage(1, // WidevinePsshData widevine_pssh_data
            protobuf.NewBytes(1, psshData), // bytes pssh_data
         ),
      ),
   }.Encode()
   if err != nil {
      return err
   }
   return nil
}

func (r *ResponseBody) Unmarshal(data []byte) error {
   return r[0].Parse(data)
}

func (p *Pssh) Encode() ([]byte, error) {
   var data protobuf.Message
   for _, key_id := range p.KeyIds {
      data = append(data, protobuf.NewBytes(2, key_id))
   }
   if len(p.ContentId) >= 1 {
      data = append(data, protobuf.NewBytes(4, p.ContentId))
   }
   return data.Encode()
}

type Pssh struct {
   ContentId []byte
   KeyIds    [][]byte
}

// SignedMessage
// LICENSE = 2;
type ResponseBody [1]protobuf.Message

func (fill) Read(data []byte) (int, error) {
   return len(data), nil
}

type fill struct{}

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

type Cdm struct {
   license_request []byte
   private_key     *rsa.PrivateKey
}

type KeyContainer [1]protobuf.Message
