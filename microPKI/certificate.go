package microPKI

import (
	"io/ioutil"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

const (
	certificatePEMType = "CERTIFICATE"
	certificateFileFlag = os.O_WRONLY|os.O_CREATE|os.O_TRUNC
	certificateFilePerm = 0600
)

func LoadCertificatefromDerBytes(derBytes []byte) (*x509.Certificate, error) {
	crts, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}
	if len(crts) != 1 {
		err = errors.New("Unsupported multiple certificates in a block")
		return crts[0], err
	}
	return crts[0], nil
}

func LoadCertificatefromDerFile(certificateFile string) (*x509.Certificate, error) {
	certificateBits, err := ioutil.ReadFile(certificateFile)
	if err != nil {
		return nil, err
	}
	return LoadCertificatefromDerBytes(certificateBits)
}

func LoadCertificatefromPEMFile(certificateFile string) (*x509.Certificate, error) {
	certificateBits, err := ioutil.ReadFile(certificateFile)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(certificateBits)
	if pemBlock == nil {
		err = errors.New("Can NOT find PEM formatted block")
		return nil, err
	}
	if pemBlock.Type != certificatePEMType || len(pemBlock.Headers) != 0 {
		err = errors.New("Unmatched type or headers")
		return nil, err
	}
	return LoadCertificatefromDerBytes(pemBlock.Bytes)
}

func DumpCertificatetoPEMFile(certificate *x509.Certificate, outputFilePath string) error {
	certificateFile, err := os.OpenFile(outputFilePath, certificateFileFlag, certificateFilePerm)
	defer certificateFile.Close()
	if err != nil {
		return err
	}
	pemBlock := &pem.Block{
		Type:    certificatePEMType,
		Headers: nil,
		Bytes:   certificate.Raw,
	}
	if err := pem.Encode(certificateFile, pemBlock); err != nil {
		return err
	}
	return nil
}

func DumpCertificatetoDERFile(certificate *x509.Certificate, outputFilePath string) error {
	certificateFile, err := os.OpenFile(outputFilePath, certificateFileFlag, certificateFilePerm)
	defer certificateFile.Close()
	if err != nil {
		return err
	}
	certificateFile.Write(certificate.Raw)
	return nil
}