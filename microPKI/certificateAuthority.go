package microPKI

import (
	"time"
	"crypto/x509"
	"math/big"
	"crypto/x509/pkix"
	"crypto/rsa"
	"crypto/rand"
	"log"
	"encoding/json"
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
func (pki *MicroPkI) CreateCertificateAuthority(key *rsa.PrivateKey, organizationalUnit string, years int, organization string, country string, province string, locality string, commonName string) (*x509.Certificate, error) {
	subjectKeyID, err := pki.GenerateSubjectKeyID(key.Public)
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
func (pki *MicroPkI) createIntermediateCertificateAuthority(csr *x509.CertificateRequest, expYear int, expMonths int, expDays int) (*x509.Certificate, error) {
	/*
	// Random Serial Number

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	*/
	raw, err := pki.db.Get([]byte(KeySerialNumber), nil)
	if err != nil {
		log.Fatal("DB Failed: [createIntermediateCertificateAuthority] ", err)
	}
	serialNumber := big.NewInt(0).SetBytes(raw)
	serialNumber = serialNumber.Add(serialNumber, big.NewInt(1)) // SerialNumber increase once
	authTemplate.SerialNumber.Set(serialNumber)
	authTemplate.MaxPathLenZero = false


	authTemplate.RawSubject = csr.RawSubject

	caExpiry := pki.caCert.NotAfter
	proposedExpiry := time.Now().AddDate(expYear, expMonths, expDays).UTC()
	// ensure cert doesn't expire after issuer
	if caExpiry.Before(proposedExpiry) {
		authTemplate.NotAfter = caExpiry
	} else {
		authTemplate.NotAfter = proposedExpiry
	}

	authTemplate.SubjectKeyId, err = pki.GenerateSubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	authTemplate.IPAddresses = csr.IPAddresses
	authTemplate.DNSNames = csr.DNSNames


	crtOutBytes, err := x509.CreateCertificate(rand.Reader, &authTemplate, pki.caCert, csr.PublicKey, pki.caKey)
	if err != nil {
		return nil, err
	}

	cert, err :=  LoadCertificatefromDerBytes(crtOutBytes)
	if err != nil {
		return nil, err
	}
	err = pki.recordCertificateSigning(cert)
	if err != nil {
		log.Fatal("Record Failed: ", err)
		return nil, err
	}
	return cert, nil
}

func (pki *MicroPkI) recordCertificateSigning(cert *x509.Certificate) error {
	record := certSignRecord{
		commenName: cert.Subject.CommonName,
		notAfter: cert.NotAfter,
		notBefore: cert.NotBefore,
		serialNumber: *cert.SerialNumber,
	}
	err := pki.db.Put([]byte(KeySerialNumber), record.serialNumber.Bytes(), nil)
	if err != nil {
		log.Fatal("DB faild: [recordCertificateSigning] ",  err)
		return err
	}
	jsonRecord, err := json.Marshal(record)
	if err != nil {
		log.Fatal(err)
	}
	err = pki.db.Put([]byte(keyCertPrefix + record.commenName), []byte(jsonRecord), nil)
	if err != nil {
		log.Fatal("DB faild: [recordCertificateSigning] ",  err)
		return err
	}
	return nil
}

