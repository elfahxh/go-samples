package ecc25519

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"crypto/ed25519"
	"encoding/hex"
	"encoding/pem"
)

//生成私钥公钥对
func (es *Curve) MakeKey() (err error) {
	es.pub, es.key, err = ed25519.GenerateKey(rand.Reader)
	//fmt.Printf("Key String: [%s]\n", strings.ToUpper(hex.EncodeToString(es.key[:])))
	fmt.Printf("Key String: [%s]\n", hex.EncodeToString(es.key[:]))
	es.SetKey(es.key)
	return err
}

//如果只需要验证签名，只要公钥就可以了，一般验证签名方也没有私钥
//pub32 必须长度大于 32，并且只取前 32 字节
func (es *Curve) SetPublic(pub32 *[ed25519.PublicKeySize]byte) {
	copy(es.key[32:], pub32[:32])
	PublicKeyToCurve25519(&es._public, pub32)
}
func (es *Curve) SetPublicBytes(pub32 []byte) (*[ed25519.PublicKeySize]byte, error) {
	if len(pub32) < 32 {
		return nil, errors.New("input data must bigger then 32 bytes")
	}
	copy(es.key[32:], pub32[:32])
	p32 := new([ed25519.PublicKeySize]byte)
	copy(p32[:], pub32)
	PublicKeyToCurve25519(&es._public, p32)
	return p32, nil
}
func (es *Curve) GetPublic() *[ed25519.PublicKeySize]byte {
	pub := new([ed25519.PublicKeySize]byte)
	copy(pub[:], es.key[32:])
	return pub
}
func (es *Curve) SetPublicHex(pub string) error {
	p, err := hex.DecodeString(pub)
	if err != nil {
		return err
	}
	if len(p) != ed25519.PublicKeySize {
		return errors.New("字串解码字节数不是[" + strconv.Itoa(ed25519.PublicKeySize) + "]")
	}
	p32 := new([ed25519.PublicKeySize]byte)
	copy(p32[:], p)
	es.SetPublic(p32)
	return nil
}
func (es *Curve) GetPublicHex() string {
	return strings.ToUpper(hex.EncodeToString(es.key[32:]))
}

//如果要签名必须设置私钥，需要注意的是，还需要设置公钥，因为真正的私钥实际上是公钥私钥的组合
func (es *Curve) SetPrivate(pri *[ed25519.PublicKeySize]byte) error {
	copy(es.key[:32], pri[:])
	PrivateKeyToCurve25519(&es._private, pri)
	return nil
}
func (es *Curve) GetPrivate() []byte {
	pri := make([]byte, 32)
	copy(pri, es.key[:32])
	return pri
}
func (es *Curve) SetPrivateHex(pri string) error {
	p, err := hex.DecodeString(pri)
	if err != nil {
		return err
	}
	if len(p) != ed25519.PublicKeySize {
		return errors.New("字串解码字节数不是[" + strconv.Itoa(ed25519.PublicKeySize) + "]")
	}
	p32 := new([ed25519.PublicKeySize]byte)
	copy(p32[:], p)
	return es.SetPrivate(p32)
}
func (es *Curve) GetPrivateHex() string {
	return strings.ToUpper(hex.EncodeToString(es.key[:32]))
}
func (es *Curve) GetKey() []byte {
	key := make([]byte, 64)
	copy(key, es.key[:])
	return key
}
func (es *Curve) SetKey(key []byte) error {
	copy(es.key[:], key[:64])
	// if len(key) < 64 {
	// 	fmt.Printf("Error! key length require at least 64 bytes!")
	// 	return errors.New("key length require at least 64 bytes")
	// }
	// copy(es.key[:], key[:64])

	pem.Encode(os.Stdout, &pem.Block{Type: "ED25519 KEY", Bytes: es.key[:]})

	var _pri, _pub [32]byte
	copy(_pri[:], key[:32])
	copy(_pub[:], key[32:])

	pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: _pri[:]})

	PrivateKeyToCurve25519(&es._private, &_pri)
	PublicKeyToCurve25519(&es._public, &_pub)
	fmt.Printf("Curve25519 hex key pairs[%s]/[%s]\n", strings.ToUpper(hex.EncodeToString(es._private[:])), strings.ToUpper(hex.EncodeToString(es._public[:])))
	fmt.Printf("Private PEM String: [%s]\n", pem.Encode(os.Stdout, &pem.Block{Type: "curve25519 PRIVATE KEY", Bytes: es._private[:]}))

	fmt.Printf("Public PEM String: [%s]\n", pem.Encode(os.Stdout, &pem.Block{Type: "curve25519 PUBLIC KEY", Bytes: es._public[:]}))

	return nil
}
func (es *Curve) GetKeyString() string {
	return strings.ToUpper(hex.EncodeToString(es.key[:]))
}
func (es *Curve) SetKeyString(key string) error {
	k, err := hex.DecodeString(key)
	if err != nil {
		return err
	}
	return es.SetKey(k)
}
func (es *Curve) Sign(data []byte) []byte {
	sign := ed25519.Sign(es.key, data)
	return sign
}

func (es *Curve) Verify(sign []byte, data []byte) bool {
	copy(es.pub[:], es.key[32:])
	return ed25519.Verify(es.pub, data, sign)
}
