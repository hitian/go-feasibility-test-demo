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

	encryptMessage, err := c.Encode([]byte(message))
	assert.Nil(err)
	// fmt.Println("encrypted message: ", string(encryptMessage))

	assert.NotEqual(message, encryptMessage)

	//decode
	originMessage, err := c.Decode(encryptMessage)
	assert.Nil(err)
	fmt.Println("decoded message: ", string(originMessage))
	assert.Equal(message, string(originMessage))

	_, err = CreateNewKey(1)
	assert.NotNil(err, "wrong key length should fail")

	otherKey, _ := CreateNewKey(128)
	_, err = otherKey.Decode(encryptMessage)
	assert.NotNil(err, "wrong key should decode fail")

	messageSizeTestKey, _ := CreateNewKey(256)
	publicKeySize := messageSizeTestKey.PrivateKey.PublicKey.Size()
	fmt.Printf("public key size: %#v\n", publicKeySize)

	//the message size should not lt publicKeySize - 11
	toLongMessage := strings.Repeat("1", publicKeySize-10)
	_, err = messageSizeTestKey.Encode([]byte(toLongMessage))
	assert.NotNil(err, "encrypt to long message should fail")

	okSizeMessage := strings.Repeat("1", publicKeySize-11)
	_, err = messageSizeTestKey.Encode([]byte(okSizeMessage))
	assert.Nil(err, "encrypt message should ok")

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

	encryptMessage, err := c.Encode([]byte(message))
	assert.Nil(err)
	assert.NotEqual(encryptMessage, []byte(message))

	originMessage, err := c.Decode(encryptMessage)
	assert.Nil(err)
	assert.Equal(originMessage, []byte(message), "message should be equal after encrypt and decrypt by the same key pair")

}
