package microPKI

import (
	"github.com/syndtr/goleveldb/leveldb"
	"crypto/x509"
	"crypto/rsa"
	"log"
	"errors"
	"math/big"
	"strconv"
)

type MicroPkI struct {
	db leveldb.DB

	caCert *x509.Certificate
	caKey *rsa.PrivateKey
}

const (
	keyCaCertFile = "CA_CERT_FILE"
	keyCaKeyFile = "CA_KEY_FILE"
	KeySerialNumber = "SERIAL_NUMBER"
	keyCertPrefix = "CERT-"
	pkiDateBaseName = "PKI_DATABASE"
	initSerialNumber = 1000
)

var (
	PROD_PKI MicroPkI
	DEV_PKI MicroPkI
)

func NewMicroPKI_INTERNAL_PRIVATE_FUNCTION(caCert string, caKey string, dbPath string) *MicroPkI {
	/*
	PRIVATE METHOD
	DO NOT USE IN PRODUT ENV
	 */
	db, err := leveldb.OpenFile(dbPath+"/"+pkiDateBaseName, nil)
	if err != nil {
		log.Fatal("Can not open leveldb, ", err)
	}
	pki := MicroPkI{db: *db}
	err = pki.ReBuildService()
	if err != nil{
		pki.initCAServiceFromExistCert(caCert, caKey)
	}
	return &pki
}

func NewMircoPKI(caCert string, caKey string) *MicroPkI {
	db, err := leveldb.OpenFile(pkiDateBaseName, nil)
	if err != nil {
		log.Fatal("Can not open leveldb, ", err)
	}
	pki := MicroPkI{db: *db}
	err = pki.ReBuildService()
	if err != nil{
		pki.initCAServiceFromExistCert(caCert, caKey)
	}
	return &pki
}

func (caSvc *MicroPkI) buildCAService(caCert string, caKey string) error {
	cert, err := LoadCertificatefromPEMFile(caCert)
	if err != nil {
		log.Fatal("Load CA Cert failed: ", err)
		return err
	}
	caSvc.caCert = cert
	key, err := caSvc.LoadRSAKeyfromFile(caKey)
	if err != nil {
		log.Fatal("Load CA Key failed: ", err)
		return err
	}
	caSvc.caKey = key
	caSvc.db.Put([]byte(keyCaCertFile), []byte(caCert), nil)
	caSvc.db.Put([]byte(keyCaKeyFile), []byte(caKey), nil)
	// TODO
	caSvc.db.Put([]byte(KeySerialNumber), big.NewInt(initSerialNumber).Bytes(), nil)
	return nil
}

func (caSvc *MicroPkI) initCAServiceFromExistCert(caCert string, caKey string) error {
	hasCACertinDB, err := caSvc.db.Has([]byte(keyCaCertFile), nil)
	if err != nil {
		log.Fatal(err)
		return err
	}
	if hasCACertinDB {
		err := errors.New("Exist old CA cert, can NOT execute init..")
		log.Println("Init failed: ", err)
		return err
	}
	return caSvc.buildCAService(caCert, caKey)
}

func (caSvc *MicroPkI) ReBuildService() error {
	hasCACertinDB, err := caSvc.db.Has([]byte(keyCaCertFile), nil)
	if err != nil {
		log.Fatal("Rebuild failed: ", err)
		return err
	}
	if !hasCACertinDB {
		err := errors.New("No CA Cert exist!")
		log.Println("Rebuild failed: ", err)
		return err
	}
	caCertFile, err := caSvc.db.Get([]byte(keyCaCertFile), nil)
	if err != nil {
		log.Fatal(err)
	}
	caKeyFile, err := caSvc.db.Get([]byte(keyCaKeyFile), nil)
	if err != nil {
		log.Fatal(err)
	}
	return caSvc.buildCAService(string(caCertFile), string(caKeyFile))
}

func (caSvc *MicroPkI) IsCALoaded() bool {
	if caSvc.caCert != nil {
		return true
	} else {
		return false
	}
}

func (caSvc *MicroPkI) SignCert(csr *x509.CertificateRequest, expYears int, expMonths int, expDays int) (*x509.Certificate, error) {
	cert, err := caSvc.createIntermediateCertificateAuthority(csr, expYears, expMonths, expDays)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return cert, nil
}


func (caSvc *MicroPkI) GetCertAlertAble(cn string, level int) bool {
	hasAlertFlag, err := caSvc.db.Has([]byte(cn+strconv.Itoa(level)), nil)
	if err != nil {
		log.Fatal(err)
		return false
	}
	if hasAlertFlag {
		alertAble, err := caSvc.db.Get([]byte(cn+strconv.Itoa(level)), nil)
		if err != nil {
			log.Fatal(err)
			return false
		}
		if string(alertAble) == "T" {
			return true
		} else {
			return false
		}
	}
	return true
}

func (caSvc *MicroPkI) SetCertAlertAble(cn string, level int, flag bool) bool {
	var f string
	if flag {
		f = "T"
	}else {
		f = "F"
	}
	err := caSvc.db.Put([]byte(cn+strconv.Itoa(level)), []byte(f), nil)
	if err != nil {
		log.Fatal(err)
		return false
	}
	return true
}