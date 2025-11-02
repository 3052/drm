# ECDSA

with Go 1.26, these are deprecated:

- https://pkg.go.dev/crypto/ecdsa@go1.25rc1#PublicKey.X
- https://pkg.go.dev/crypto/ecdsa@go1.25rc1#PublicKey.Y

which means we cannot use them to marshal. this gets added:

https://pkg.go.dev/crypto/ecdsa@go1.25rc1#PublicKey.Bytes

but its the incorrect 65 byte format. we could derive X and Y from D, but its
deprecated also:

https://pkg.go.dev/crypto/ecdsa@go1.25rc1#PrivateKey.D

which means we would need to marshal the private key:

https://pkg.go.dev/crypto/ecdsa@go1.25rc1#PrivateKey.Bytes

then unmarshal:

https://pkg.go.dev/math/big#Int.SetBytes

then multiply:

https://pkg.go.dev/github.com/starkbank/ecdsa-go/v2/ellipticcurve/math#Multiply
