package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

var (
	DefaultKeyPairLength = 2048

	DefaultMessageLabel = ""
)

const (
	ErrorPrivateKey = "private key does not registered or invalid"
	ErrorPublicKey  = "public key does not registered or invalid"
)

type KeyPair struct {
	private        *rsa.PrivateKey // your own private key
	public         *rsa.PublicKey  // your own public key
	alienPublicKey *rsa.PublicKey  // public key of interlocutor

	secretMessage []byte // encrypted message
	signature     []byte // signature of message
}

// NewKeyPair function generates / imports rsa.PrivateKey
func NewKeyPair(privateKey *rsa.PrivateKey) (*KeyPair, error) {
	var err error

	if privateKey == nil {
		privateKey, err = rsa.GenerateKey(rand.Reader, DefaultKeyPairLength)
		if err != nil {
			return nil, err
		}
	}

	return &KeyPair{
		private: privateKey,
		public:  &privateKey.PublicKey,
	}, nil
}

// Serialize function converts rsa.PrivateKey to string
// If private key is not already registered than will catch an error
func (keyPair *KeyPair) Serialize() (string, error) {

	if keyPair.private == nil {
		return "", errors.New(ErrorPrivateKey)
	}

	var data = x509.MarshalPKCS1PrivateKey(keyPair.private)

	return hex.EncodeToString(data), nil
}

// EncryptWithAlienPubKey function encrypt a message suing another public key
// In other words if you want to send a secret message to another user you will need to encrypt
// you message using his public key
func (keyPair *KeyPair) EncryptWithAlienPubKey(message string) (string, error) {

	if keyPair.alienPublicKey == nil {
		return "", errors.New(ErrorPublicKey)
	}

	var hash = sha256.New()

	cipherText, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		keyPair.alienPublicKey,
		[]byte(message),
		[]byte(DefaultMessageLabel),
	)

	keyPair.secretMessage = cipherText

	return hex.EncodeToString(cipherText), err
}

// SignMessage function signs the message which you want to send to another user.
// That user can verify that the sender is real using your public key
func (keyPair *KeyPair) SignMessage(message string) (string, error) {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto

	newHash := crypto.SHA256
	pssh := newHash.New()
	pssh.Write([]byte(message))

	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(
		rand.Reader,
		keyPair.private,
		newHash,
		hashed,
		&opts,
	)

	keyPair.signature = signature

	return hex.EncodeToString(signature), err

}

// Decrypt function decrypts a cipher text using your private key
func (keyPair *KeyPair) Decrypt(message string) (string, error) {

	var hash = sha256.New()

	plainText, err := rsa.DecryptOAEP(
		hash,
		rand.Reader,
		keyPair.private,
		[]byte(message),
		[]byte(DefaultMessageLabel),
	)

	return hex.EncodeToString(plainText), err
}

func (keyPair *KeyPair) ImportAlienPublicKey(publicKey *rsa.PublicKey) {
	keyPair.alienPublicKey = publicKey
}
