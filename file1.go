package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}

	publicKey := privateKey.PublicKey
	pemPrivateFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pemPrivateBlock = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPrivateFile.Close()

	initialMessage := "I am Raj Kumar."

	encryptedMessage := RSA_OAEP_Encrypt(initialMessage, publicKey)

	createFile1()

	var file, err1 = os.OpenFile("em.text", os.O_RDWR, 0644)
	CheckError(err1)

	// Write some text line-by-line to file.
	_, err = file.WriteString(encryptedMessage)
	CheckError(err)

	// Save file changes.
	err = file.Sync()
	CheckError(err)

	h1 := sha256.New()
	h1.Write([]byte(initialMessage))
	bx1 := h1.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, bx1, nil)
	CheckError(err)

	createFile2()

	var file2, err2 = os.OpenFile("sign.text", os.O_RDWR, 0644)
	CheckError(err2)

	// Write some text line-by-line to file.
	_, err = file2.Write(signature)
	CheckError(err)

	// Save file changes.
	err = file2.Sync()
	CheckError(err)

	createFile3()

	var file3, err3 = os.OpenFile("bx1.text", os.O_RDWR, 0644)
	CheckError(err3)

	// Write some text line-by-line to file.
	_, err = file3.Write(bx1)
	CheckError(err)

	// Save file changes.
	err = file2.Sync()
	CheckError(err)
}

func RSA_OAEP_Encrypt(secretMessage string, key rsa.PublicKey) string {
	label := []byte("OAEP Encrypted")                                                            //[]byte: represents byte stream
	rng := rand.Reader                                                                           //Random reader used for generating random bits so that no two input has same output
	encryptedText, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label) //key: public and private keys are generated previously.
	CheckError(err)
	return base64.StdEncoding.EncodeToString(encryptedText)
}

func CheckError(e error) {
	if e != nil {
		fmt.Println(e.Error())
	}
}

func createFile1() {
	var file2, err = os.Create("em.text")
	CheckError(err)
	defer file2.Close()
}

func createFile2() {
	var file2, err = os.Create("sign.text")
	CheckError(err)
	defer file2.Close()
}

func createFile3() {
	var file3, err = os.Create("bx1.text")
	CheckError(err)
	defer file3.Close()
}
