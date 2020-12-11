package main

import (
	"fmt"

	"hexiaohu.cn.ibm/wireguard/pkged25519"
	"hexiaohu.cn.ibm/wireguard/pkgx509"
)

func main() {

	fmt.Println("Entering main....")
	//pkgwireguard.TestWireguard()
	pkged25519.DecodeED25519PrivatePEM()
	pkged25519.DecodeED25519PublicPEM()
	pkgx509.TestCSR()
}
