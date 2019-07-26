package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
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

//ExportPublicKey to base64 string
func (c *Crypto) ExportPublicKey() string {
	key := x509.MarshalPKCS1PublicKey(&c.PrivateKey.PublicKey)
	return base64.StdEncoding.EncodeToString(key)
}

//ParseKey parse private key from base64 string
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

//Encrypt message use the public key
func (c *Crypto) Encrypt(message []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &c.PrivateKey.PublicKey, message)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

//Decrypt message use the private key
func (c *Crypto) Decrypt(message []byte) ([]byte, error) {
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, c.PrivateKey, message)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

//Sign input use sha256 hash
func (c *Crypto) Sign(input []byte) ([]byte, error) {
	hashed := sha256.Sum256(input)
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func publicKeyStringToKey(publicKey string) (*rsa.PublicKey, error) {
	rawKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("key base64 decode failed [%s]", err)
	}

	key, err := x509.ParsePKCS1PublicKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("key parse failed [%s]", err)
	}
	return key, nil
}

//EncryptWithPublicKey encrypt message with base64-public-key-string
func EncryptWithPublicKey(message []byte, publicKey string) ([]byte, error) {
	key, err := publicKeyStringToKey(publicKey)
	if err != nil {
		return nil, err
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, key, message)
	if err != nil {
		return nil, fmt.Errorf("encrypt failed [%s]", err)
	}
	return encrypted, nil
}

//SignVerifyWithPublicKey verify the signature signed by Sign function
func SignVerifyWithPublicKey(input, signature []byte, publicKey string) error {
	key, err := publicKeyStringToKey(publicKey)
	if err != nil {
		return err
	}
	hashed := sha256.Sum256(input)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature)
}
