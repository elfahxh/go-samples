package main

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
	wg "golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
)

var (
	logger          = log.New(os.Stdout, "<Netlink>", log.Lshortfile|log.Ldate|log.Ltime)
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

// ED25519Singer signer
type ED25519Singer struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func NewED25519Singer() (*ED25519Singer, error) {

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)

	logger.Printf("Key HEX String: [%s]\n", strings.ToUpper(hex.EncodeToString(privKey[:])))

	logger.Printf("Key PEM String: [%s]\n", pem.Encode(os.Stdout, &pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: privKey}))

	logger.Printf("Public PEM String: [%s]\n", pem.Encode(os.Stdout, &pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pubKey}))

	signer := &ED25519Singer{
		publicKey:  pubKey,
		privateKey: privKey}
	return signer, err
}

func (s *ED25519Singer) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *ED25519Singer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return ed25519.Sign(s.privateKey, digest), nil
}

func testWireguard() {
	wg0, _ := netlink.LinkByName("wg0")

	if wg0 != nil {
		logger.Println("delete link....")
		netlink.LinkDel(wg0)
	}

	la := netlink.NewLinkAttrs()
	la.Name = "wg0"
	mywireguard := &netlink.Wireguard{LinkAttrs: la}
	logger.Println("add link....")
	err := netlink.LinkAdd(mywireguard)
	if err != nil {
		logger.Printf("could not add %s: %v\n", la.Name, err)
	}
	cmd := exec.Command("bash", "-c", "ip link show type wireguard")
	out, _ := cmd.CombinedOutput()
	logger.Printf("ip link show type wireguard:\n%s\n", string(out))
	// err = netlink.LinkDel(mywireguard)
	// if err != nil {
	// 	fmt.Printf("could not del %s: %v\n", la.Name, err)
	// }
	// cmd = exec.Command("bash", "-c", "ip link show type wireguard")
	// out, _ = cmd.CombinedOutput()
	// fmt.Printf("ip link show type wireguard:\n%s\n", string(out))
	wg0, _ = netlink.LinkByName("wg0")
	addr, _ := netlink.ParseAddr("10.0.0.1/24")
	netlink.AddrAdd(wg0, addr)
	netlink.LinkSetUp(wg0)
	cmd = exec.Command("bash", "-c", "ifconfig wg0")
	out, _ = cmd.CombinedOutput()
	logger.Printf("ifconfig wg0:\n%s\n", string(out))

	wgc, err := wg.New()

	wgd, err := wgc.Device("wg0")

	logger.Printf("Device name = [%s] [%s], [%d], [PrivateKey:%s], [%v]", wgd.Name, wgd.Type, wgd.ListenPort, string(wgd.PrivateKey[:]), wgd)
}

func decodeED25519PrivatePEM() {
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

func decodeED25519PublicPEM() {
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

func testCSR() {

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Printf("GeneratePrivateKey failed....%v", err)
	}
	pubKey := key.PublicKey()

	logger.Printf("privateKey[%s], pubKey[%s] \n", key, pubKey)

	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)

	logger.Printf("keyBytes: %v \n", keyBytes)

	// emailAddress := "test@example.com"
	// subj := pkix.Name{
	// 	CommonName:         "example.com",
	// 	Country:            []string{"AU"},
	// 	Province:           []string{"Some-State"},
	// 	Locality:           []string{"MyCity"},
	// 	Organization:       []string{"Company Ltd"},
	// 	OrganizationalUnit: []string{"IT"},
	// }
	// rawSubj := subj.ToRDNSequence()
	// rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
	// 	{Type: oidEmailAddress, Value: emailAddress},
	// })
	// asn1Subj, _ := asn1.Marshal(rawSubj)
	// template := x509.CertificateRequest{
	// 	RawSubject:         asn1Subj,
	// 	EmailAddresses:     []string{emailAddress},
	// 	SignatureAlgorithm: x509.PureEd25519,
	// }

	// siger, _ := NewED25519Singer()

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "example.com",
			Country:            []string{"AU"},
			Province:           []string{"Some-State"},
			Locality:           []string{"MyCity"},
			Organization:       []string{"Company Ltd"},
			OrganizationalUnit: []string{"IT"},
		},
		SignatureAlgorithm: x509.PureEd25519,
		DNSNames:           []string{"test.example.com"},
		EmailAddresses:     []string{"gopher@golang.org"},
		IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
	}

	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, ed25519Priv)
	if err != nil {
		logger.Printf("CreateCertificateRequest, error %v\n", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	out, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		logger.Fatalf("failed to create certificate request: %s", err)
	}
	err = out.CheckSignature()
	if err != nil {
		logger.Fatalf("failed to check certificate request signature: %s", err)
	}
	if out.Subject.CommonName != template.Subject.CommonName {
		logger.Fatalf("output subject common name and template subject common name don't match")
	} else if len(out.Subject.Organization) != len(template.Subject.Organization) {
		logger.Fatalf("output subject organisation and template subject organisation don't match")
	} else if len(out.DNSNames) != len(template.DNSNames) {
		logger.Fatalf("output DNS names and template DNS names don't match")
	} else if len(out.EmailAddresses) != len(template.EmailAddresses) {
		logger.Fatalf("output email addresses and template email addresses don't match")
	} else if len(out.IPAddresses) != len(template.IPAddresses) {
		logger.Fatalf("output IP addresses and template IP addresses names don't match")
	}
}

func main() {

	logger.Println("Entering main....")
	// decodeED25519PrivatePEM()
	// decodeED25519PublicPEM()
	testCSR()
}
