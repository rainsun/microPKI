package microPKI

import (
	"crypto/rsa"
	"log"
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/rand"
	"io/ioutil"
	"errors"
	"crypto"
	"encoding/asn1"
	"crypto/sha1"
)

const (
	RSA_BITS = 2048
	RSA_PRIVATE_TYPE = "RSA PRIVATE KEY"
)

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, RSA_BITS)
	if err != nil {
		log.Fatalf("Failed to generate private key: %s", err)
		return nil, err
	}

	return priv, nil
}


func DumpRSAKeytoFile(privateKey *rsa.PrivateKey, outputFilePath string) error {
	privKeyFile, err := os.OpenFile(outputFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer privKeyFile.Close()
	if err != nil {
		return  err
	}
	pem.Encode(privKeyFile, &pem.Block{Type: RSA_PRIVATE_TYPE, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return nil
}

func DumpEncryptRSAKeytoFile(privateKey *rsa.PrivateKey, passphrase string, outputFilePath string) error {
	// TODO
	return nil
}

func LoadRSAKeyfromFile(rsaKeyFile string) (*rsa.PrivateKey, error) {
	rsaKeyBits, err := ioutil.ReadFile(rsaKeyFile)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(rsaKeyBits)
	if pemBlock == nil {
		return nil, errors.New("Cannot find the RSA key")
	}
	if pemBlock.Type != RSA_PRIVATE_TYPE || len(pemBlock.Headers) != 0 {
		return nil, errors.New("Unmatched RSA type or Header")
	}

	priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func LoadEncryptRSAKeyfromFile(encryptRSAKeyFile string, passphrase string) (*rsa.PrivateKey, error) {
	// TODO
	return nil, nil
}

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// Id is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func GenerateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsa.PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only RSA public key is supported")
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}

