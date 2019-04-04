package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
)

func ToRSAPrivateKey(privateKey string) (*rsa.PrivateKey, error) {

	var private, err = hex.DecodeString(privateKey)

	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PrivateKey(private)

}

func ToRSAPublicKey(publicKey string) (*rsa.PublicKey, error) {

	var public, err = hex.DecodeString(publicKey)

	if err != nil {
		return nil, err
	}

	return x509.ParsePKCS1PublicKey(public)
}

func RSAPublicToString(public *rsa.PublicKey) string {
	var publicKey = x509.MarshalPKCS1PublicKey(public)

	return hex.EncodeToString(publicKey)
}

func RSAPrivateToString(private *rsa.PrivateKey) string {
	var publicKey = x509.MarshalPKCS1PrivateKey(private)

	return hex.EncodeToString(publicKey)
}
