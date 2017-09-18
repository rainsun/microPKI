package microPKI

import (
	"os"
	"net"
	"crypto/x509"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
)

const (
	CERTIFICATE_REQUEST_TYPE = "CERTIFICATE REQUEST"
)

var (
	csrPkixName = pkix.Name{
		Country:            []string{},
		Organization:       []string{},
		OrganizationalUnit: nil,
		Locality:           nil,
		Province:           nil,
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "",
		CommonName:         "",
	}
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)


func CreateCertificateSigningRequest(key *rsa.PrivateKey, organizationalUnit string, ipList []net.IP, domainList []string, organization string, country string, province string, locality string, commonName string, email string) ([]byte, error) {
//C = CN, ST = Beijing, L = Haidian, O = Renrendai, OU = InfTeam, CN = LyuConggang, emailAddress = ]lvconggang@we.com
	csrPkixName.CommonName = commonName

	if len(organizationalUnit) > 0 {
		csrPkixName.OrganizationalUnit = []string{organizationalUnit}
	}
	if len(organization) > 0 {
		csrPkixName.Organization = []string{organization}
	}
	if len(country) > 0 {
		csrPkixName.Country = []string{country}
	}
	if len(province) > 0 {
		csrPkixName.Province = []string{province}
	}
	if len(locality) > 0 {
		csrPkixName.Locality = []string{locality}
	}
	if email != ""{
		csrPkixName.ExtraNames = []pkix.AttributeTypeAndValue{pkix.AttributeTypeAndValue{Type: oidEmailAddress, Value: email}}
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:     csrPkixName,
		IPAddresses: ipList,
		DNSNames:    domainList,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, err
	}
	return csrBytes, nil
}

func DumpCSRFile(csrBytes []byte, outputFilePath string) error {
	// Default as PEM type
	csrFile, err := os.OpenFile(outputFilePath, certificateFileFlag, certificateFilePerm)
	defer csrFile.Close()
	if err != nil {
		return  err
	}
	pem.Encode(csrFile, &pem.Block{Type: CERTIFICATE_REQUEST_TYPE, Bytes: csrBytes})
	return nil
}