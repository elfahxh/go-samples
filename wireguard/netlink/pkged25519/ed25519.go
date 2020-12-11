package pkged25519

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	logger = log.New(os.Stdout, "<pkged25519>", log.Lshortfile|log.Ldate|log.Ltime)
)

func DecodeED25519PrivatePEM() {
	var pubPEMData = []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIhaXuhU2ngXdUfn/NPlG3sSZNfnX0cI3qtTK4NsI5Fb
-----END PRIVATE KEY-----`)

	block, rest := pem.Decode(pubPEMData)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	espriv, _ := priv.(ed25519.PrivateKey)
	logger.Printf("Got private key [%s] \n", strings.ToUpper(hex.EncodeToString(espriv[:])))

	fmt.Printf("Got a %T, with remaining data: %q \n", priv, rest)

}

func DecodeED25519PublicPEM() {
	var pubPEMData = []byte(`
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPB77nBmjVoUX1qBJYXYFARXULoAnJRrU3Nj4dNDreME=
-----END PUBLIC KEY-----`)

	block, rest := pem.Decode(pubPEMData)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing pubic key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	espub, _ := pub.(ed25519.PublicKey)
	logger.Printf("Got public key [%s] \n", strings.ToUpper(hex.EncodeToString(espub[:])))

	fmt.Printf("Got a %T, with remaining data: %q \n", pub, rest)

}
