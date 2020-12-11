package pkgx509

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"net"
	"os"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	logger = log.New(os.Stdout, "<pkgx509>", log.Lshortfile|log.Ldate|log.Ltime)
)

func TestCSR() {

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
