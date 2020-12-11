package main

import (
	"ed21559test/ecc25519"
	"fmt"
	"strings"

	"encoding/hex"
)

func main() {
	CreateKey()
	DataSign()
	DataCrypt()

	SetExistKey()
	DataSign()
	DataCrypt()
}

var curve ecc25519.Curve
var src string = "You can always define a function in Go to do what you want, than assign the function to console.log in javascript."
var srcdata []byte

func CreateKey() {
	fmt.Println("create a new pair key")
	curve.MakeKey()
	fmt.Println("private key(32 bytes):", curve.GetPrivateHex())
	curve.GetPublicHex()
	fmt.Println("public key(32 bytes):", curve.GetPublicHex())
}
func SetExistKey() {
	fmt.Println("=====> To Test an existing private key ------>")
	//set a exist key for curve
	// keys := "0824E6110F5E0BD6500855C4CF48BD15BB435175D34DC472BED58605634BDD7BDE0C2B412AB884AB9678791CF043ACD8A55F8DC5488A84C7B94E731F7F206D32"
	// keys := "72d35e076b4b5c0ff46d7b382200d53a48954f81cee3a0c2ea833f5cbe7c1fce7690e90ff8afcfdb64f22d680d17e6c853563660892a677f1a88d0c02c0c611f"
	// keys := "B7CC958CDA3048D5A07E7830F04015D1706D71F0556849512CE96EE9B228932DE5CAABE4DD237C439D00A775E082D37EE858BFE3D0C97E67EDB01292CFEB1B9A"
	// keys := "885A5EE854DA78177547E7FCD3E51B7B1264D7E75F4708DEAB532B836C23915B3C1EFB9C19A3568517D6A0496176050115D42E8027251AD4DCD8F874D0EB78C1"
	keys := "885A5EE854DA78177547E7FCD3E51B7B1264D7E75F4708DEAB532B836C23915B3C1EFB9C19A3568517D6A0496176050115D42E8027251AD4DCD8F874D0EB78C1"
	curve.SetKeyString(keys)
}
func DataSign() {
	//sign and verfy
	sign := curve.Sign(srcdata)
	if curve.Verify(sign, srcdata) {
		fmt.Println("verify success")
	} else {
		fmt.Println("verify failed")
	}
	//modify sign data
	sign[20] = 3
	if curve.Verify(sign, srcdata) {
		fmt.Println("verify success")
	} else {
		fmt.Println("verify failed")
	}
}

func DataCrypt() {
	srcdata = []byte(src)
	//encrypt data length at most 64 bytes
	var data []byte
	if len(srcdata) > 64 {
		data = srcdata[:64]
	} else {
		data = srcdata
	}
	//begin encrypt
	enc, err := curve.Encrypt(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	//print ciphertext to hex
	PrintHex("ciphertext:", enc)
	//begin decrypt
	dec, err := curve.Decrypt(enc)
	if err != nil {
		fmt.Println(err)
	}
	//print plaintext
	fmt.Println("plaintext:", string(dec))
}
func PrintHex(flag string, data []byte) {
	hex := hex.EncodeToString(data)
	hex = strings.ToUpper(hex)
	fmt.Println(flag, hex)
}
