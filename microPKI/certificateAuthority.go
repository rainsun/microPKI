package microPKI

import (
	"time"
	"crypto/x509"
	"math/big"
	"crypto/x509/pkix"
	"crypto/rsa"
	"crypto/rand"
)

var (
	authPkixName = pkix.Name{
		Country:            nil,
		Organization:       nil,
		OrganizationalUnit: nil,
		Locality:           nil,
		Province:           nil,
		StreetAddress:      nil,
		PostalCode:         nil,
		SerialNumber:       "",
		CommonName:         "",
	}
	// Build CA based on RFC5280
	authTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      authPkixName,
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Time{},
		// Used for certificate signing only
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		ExtKeyUsage:        nil,
		UnknownExtKeyUsage: nil,

		// activate CA
		BasicConstraintsValid: true,
		IsCA: true,
		// Not allow any non-self-issued intermediate CA, sets MaxPathLen=0
		MaxPathLenZero: true,

		// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
		// (excluding the tag, length, and number of unused bits)
		// **SHOULD** be filled in later
		SubjectKeyId: nil,

		// Subject Alternative Name
		DNSNames: nil,

		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}
)

// CreateCertificateAuthority creates Certificate Authority using existing key.
// CertificateAuthorityInfo returned is the extra infomation required by Certificate Authority.
func CreateCertificateAuthority(key *rsa.PrivateKey, organizationalUnit string, years int, organization string, country string, province string, locality string, commonName string) (*x509.Certificate, error) {
	subjectKeyID, err := GenerateSubjectKeyID(key.Public)
	if err != nil {
		return nil, err
	}
	authTemplate.SubjectKeyId = subjectKeyID
	authTemplate.NotAfter = time.Now().AddDate(years, 0, 0).UTC()
	if len(country) > 0 {
		authTemplate.Subject.Country = []string{country}
	}
	if len(province) > 0 {
		authTemplate.Subject.Province = []string{province}
	}
	if len(locality) > 0 {
		authTemplate.Subject.Locality = []string{locality}
	}
	if len(organization) > 0 {
		authTemplate.Subject.Organization = []string{organization}
	}
	if len(organizationalUnit) > 0 {
		authTemplate.Subject.OrganizationalUnit = []string{organizationalUnit}
	}
	if len(commonName) > 0 {
		authTemplate.Subject.CommonName = commonName
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, &authTemplate, &authTemplate, key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	ca, err := LoadCertificatefromDerBytes(crtBytes)
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// CreateIntermediateCertificateAuthority creates an intermediate
// CA certificate signed by the given authority.
func CreateIntermediateCertificateAuthority(ca *x509.Certificate, caKey *rsa.PrivateKey, csr *x509.CertificateRequest, years int) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	authTemplate.SerialNumber.Set(serialNumber)
	authTemplate.MaxPathLenZero = false



	authTemplate.RawSubject = csr.RawSubject

	caExpiry := time.Now().Add(ca.NotAfter.Sub(time.Now()))
	proposedExpiry := time.Now().AddDate(years, 0, 0).UTC()
	// ensure cert doesn't expire after issuer
	if caExpiry.Before(proposedExpiry) {
		authTemplate.NotAfter = caExpiry
	} else {
		authTemplate.NotAfter = proposedExpiry
	}

	authTemplate.SubjectKeyId, err = GenerateSubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	authTemplate.IPAddresses = csr.IPAddresses
	authTemplate.DNSNames = csr.DNSNames


	crtOutBytes, err := x509.CreateCertificate(rand.Reader, &authTemplate, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	cert, err :=  LoadCertificatefromDerBytes(crtOutBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

