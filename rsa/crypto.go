package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
)

const (
	keyLength int = 256
)

//Crypto private key and method
type Crypto struct {
	PrivateKey *rsa.PrivateKey
}

//CreateNewKey create new private key
func CreateNewKey(length int) (*Crypto, error) {
	key, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return nil, err
	}
	return &Crypto{PrivateKey: key}, nil
}

//ExportPrivateKey to base64 string
func (c *Crypto) ExportPrivateKey() string {
	key := x509.MarshalPKCS1PrivateKey(c.PrivateKey)
	return base64.StdEncoding.EncodeToString(key)
}

//ParseKey from base64 string
func ParseKey(key string) (*Crypto, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &Crypto{PrivateKey: privateKey}, nil
}

//PublicKey Get public key from private
func (c *Crypto) PublicKey() rsa.PublicKey {
	return c.PrivateKey.PublicKey
}

//Encode message use the public key
func (c *Crypto) Encode(message []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &c.PrivateKey.PublicKey, message)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

//Decode message use the private key
func (c *Crypto) Decode(message []byte) ([]byte, error) {
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, c.PrivateKey, message)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}
