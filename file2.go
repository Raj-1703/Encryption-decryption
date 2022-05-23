package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {

	privateKeyFile, err := os.Open("private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	publicKey := &privateKeyImported.PublicKey

	content, err := ioutil.ReadFile("em.text")
	CheckError(err)

	RSA_OAEP_Decrypt(string(content), *privateKeyImported)

	signature, err := ioutil.ReadFile("sign.text")
	CheckError(err)

	bx1, err := ioutil.ReadFile("bx1.text")
	CheckError(err)

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, bx1, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return
	}

	fmt.Println("signature verified")
}

func CheckError(e error) {
	if e != nil {
		fmt.Println(e.Error())
	}
}

func RSA_OAEP_Decrypt(encryptedtext string, privateKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(encryptedtext)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privateKey, ct, label)
	CheckError(err)
	fmt.Println("Plaintext:", string(plaintext))
	return string(plaintext)
}
