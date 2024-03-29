package rsa

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCryptoKeyGenerate(t *testing.T) {
	assert := assert.New(t)
	c, err := CreateNewKey(keyLength)
	assert.Nil(err, "CreateNewKey should success")
	assert.NotNil(c, "Crypto should not nil")
	message := "this is a message."

	encryptMessage, err := c.Encrypt([]byte(message))
	assert.Nil(err)
	// fmt.Println("encrypted message: ", string(encryptMessage))

	assert.NotEqual(message, encryptMessage)

	//decode
	originMessage, err := c.Decrypt(encryptMessage)
	assert.Nil(err)
	fmt.Println("decoded message: ", string(originMessage))
	assert.Equal(message, string(originMessage))

	_, err = CreateNewKey(1)
	assert.NotNil(err, "wrong key length should fail")

	otherKey, _ := CreateNewKey(128)
	_, err = otherKey.Decrypt(encryptMessage)
	assert.NotNil(err, "wrong key should decode fail")

	messageSizeTestKey, _ := CreateNewKey(256)
	publicKeySize := messageSizeTestKey.PrivateKey.PublicKey.Size()
	fmt.Printf("public key size: %#v\n", publicKeySize)

	//the message size should not lt publicKeySize - 11
	toLongMessage := strings.Repeat("1", publicKeySize-10)
	_, err = messageSizeTestKey.Encrypt([]byte(toLongMessage))
	assert.NotNil(err, "encrypt to long message should fail")

	okSizeMessage := strings.Repeat("1", publicKeySize-11)
	_, err = messageSizeTestKey.Encrypt([]byte(okSizeMessage))
	assert.Nil(err, "encrypt message should ok")

	testPublicKeyEncrypt, _ := CreateNewKey(256)
	publicKeyString := testPublicKeyEncrypt.ExportPublicKey()

	encryptedMessage, err := EncryptWithPublicKey([]byte(message), publicKeyString)
	assert.Nil(err, "encrypt with public key string should ok")

	originMessage, err = testPublicKeyEncrypt.Decrypt(encryptedMessage)
	assert.Nil(err, "decrypt message encrypt with public key string should ok")

	assert.Equal([]byte(message), originMessage, "decrypted message encrypt with public key string should equal")

	_, err = EncryptWithPublicKey([]byte(message), "not_base64_string")
	assert.NotNil(err, "EncryptWithPublicKey shuild fail with not base64 string key")

	_, err = EncryptWithPublicKey([]byte(message), "MTIzNA==")
	assert.NotNil(err, "EncryptWithPublicKey shuild fail with base64-and-not-key string")

	overSizeMessage := strings.Repeat("1", 100)
	_, err = EncryptWithPublicKey([]byte(overSizeMessage), publicKeyString)
	assert.NotNil(err, "encrypt overSizeMessage with public key string should fail")

	signTestKey, _ := CreateNewKey(1024)
	messageNeedToSign := []byte("message need to sign")

	sign, err := signTestKey.Sign(messageNeedToSign)
	assert.Nil(err, "sign with private key should ok")

	err = SignVerifyWithPublicKey(messageNeedToSign, sign, signTestKey.ExportPublicKey())
	assert.Nil(err, "sign verify should ok")

	err = SignVerifyWithPublicKey(messageNeedToSign[1:], sign, signTestKey.ExportPublicKey())
	assert.NotNil(err, "changed input sign verify should fail")

	err = SignVerifyWithPublicKey(messageNeedToSign[1:], sign, "MTIzNA==")
	assert.NotNil(err, "sign verify with wrong format public key should fail")

	smallSignTestKey, _ := CreateNewKey(128)
	_, err = smallSignTestKey.Sign(messageNeedToSign)
	assert.NotNil(err, "sign with a not enough length key should fail")
}

func TestImportExport(t *testing.T) {
	assert := assert.New(t)
	testPrivateKey := "MIGqAgEAAiEA1en5h7CgN3EC8g+P96LXcbKcR2gJxfbKZzRYyQBO16ECAwEAAQIgV9Ww7jRqNRmkWfxl4wrsZzTMUWs2ySshIIrj9k7JTgECEQD1BRVzFGGBW2jq9r4w62iRAhEA34AJuHPlLEsX+NvH2WGGEQIQesUPWFhP+wcYbRMxfUWXYQIRAME8u6rOEWwNdSmGJLFvX3ECEGiDZntSfGPAaK26lvfKkiw="

	c, err := ParseKey(testPrivateKey)
	assert.Nil(err, "Import key should ok")

	_, err = ParseKey("not_key")
	assert.NotNil(err, "not base64 string should parse failed")

	_, err = ParseKey("MTIzNA==")
	assert.NotNil(err, "base64 string but not key should parse failed")

	c, _ = ParseKey(testPrivateKey)
	exportKey := c.ExportPrivateKey()
	assert.Equal(exportKey, testPrivateKey, "exported key and imported key should equal")
	publicKey := c.PublicKey()
	assert.NotNil(publicKey, "public key should not nil")

	message := "this is a message."

	encryptMessage, err := c.Encrypt([]byte(message))
	assert.Nil(err)
	assert.NotEqual(encryptMessage, []byte(message))

	originMessage, err := c.Decrypt(encryptMessage)
	assert.Nil(err)
	assert.Equal(originMessage, []byte(message), "message should be equal after encrypt and decrypt by the same key pair")

}
