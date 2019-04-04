
even-crypto-go is a simple and flexible package to encrypt and decrypt message, also sign it before sending

### Packages
This package used built-in `crypto` packages and his sub-packages

### Installation
```sh
 go get github.com/gasparyanyur/even-crypto-go
```

### Usage
```code

// getting a new key-pair

var keyPair , err = crypto.NewKeyPair(nil)

if err != nil {
  panic(err)
}

fmt.Println(keyPair.Serialize())

// to get key-pair using private key

var rsaPrivateKey  = "your_rsa_private_key_here"

var privateKey ,err = crypto.ToRSAPrivateKey(rsaPrivateKey)

if err != nil {
  panic(err)
}

fmt.Println(privateKey)

```
