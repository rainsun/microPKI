package utils

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"
	"fmt"
	"signCert/mail"
	"signCert/microPKI"
	"strconv"
	"signCert/config"
)

const (
	caCertFilePath = "/private/ca.crt"
	caKeyFilePath = "/private/ca.key"
	userCertFilePath = "/users/"
	devOU = "Infteam"
	prodOU = "Infrastructure Team"
)

var CONFIG config.ConfigStruct
var successNotifyMailTile string = "[INFR PKI] [%s] Cert signed for %s"
var successNotifyMailBody string = "%s's cert has been signed!\n Please download attachment as archive of the cert!"

type Cert struct {
	Filename, Subject, Exp, Issuer string
}

type Certs struct {
	Crt []Cert
}

func GetCertsList(env string) Certs {
	cs := Certs{[]Cert{}}

	var path string =""

	if env == "PROD" {
		path = CONFIG.ProdCAPath
	} else {
		path = CONFIG.DevCAPath
	}

	files, _ := ioutil.ReadDir(path + userCertFilePath)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), "crt") || strings.HasSuffix(f.Name(), "pem") {
			filePathName := path + userCertFilePath + f.Name()
			certFile, _ := ioutil.ReadFile(filePathName)
			pemBlock, _ := pem.Decode(certFile)
			if pemBlock == nil {
				log.Println("Parse cert fail: ", filePathName)
				continue
			}
			if pemBlock.Type != "CERTIFICATE" || len(pemBlock.Headers) != 0 {
				log.Println("Parse cert fail: ", filePathName)
				continue
			}

			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				log.Fatal(filePathName, err)
				continue
			}

			if len(cert.Subject.CommonName) == 0 {
				continue
			}
			c := Cert{Filename: f.Name(), Subject: getDNfromPkiName(cert.Subject), Exp: cert.NotAfter.UTC().Format("2006-01-02 15:04:05"), Issuer: getDNfromPkiName(cert.Issuer)}
			cs.Crt = append(cs.Crt, c)
		}
	}
	return cs
}


// TODO
func GetCertDetail(certFileName string, env string) string {
	var path string =""

	if env == "PROD" {
		path = CONFIG.ProdCAPath
	} else {
		path = CONFIG.DevCAPath
	}
	out, err := exec.Command("openssl", "x509", "-noout", "-text", "-in", path+"/users/"+certFileName).Output()
	if err != nil {
		return err.Error()
	}
	return string(out)
}

func getDNfromPkiName(name pkix.Name) string {
	subject := ""
	for _, c := range name.Country {
		subject += "C=" + c + ", "
	}
	for _, st := range name.StreetAddress {
		subject += "ST=" + st + ", "
	}
	for _, l := range name.Locality {
		subject += "L=" + l + ", "
	}
	for _, o := range name.Organization {
		subject += "O=" + o + ", "
	}
	for _, ou := range name.OrganizationalUnit {
		subject += "OU=" + ou + ", "
	}
	subject += "CN=" + name.CommonName
	return subject
}

func SignCert(cn string, email string, days string, env string) bool {
	var path string =""
	ou := ""
	if env == "PROD" {
		path = CONFIG.ProdCAPath
		ou = prodOU
	} else {
		path = CONFIG.DevCAPath
		ou = devOU
	}

	pki := microPKI.NewMicroPKI_INTERNAL_PRIVATE_FUNCTION(path+caCertFilePath, path+caKeyFilePath, path)
	privateKey, err := pki.GenerateRSAKey()
	if err != nil {
		log.Fatal("Generate private key failed: ", err)
		return false
	}
	csr, err := pki.GenerateCertificateSigningRequest(privateKey, ou, nil, nil, "Renrendai", "CN", "Beijing", "Haidian", cn, email)
	if err != nil {
		log.Fatal("Generate csr failed: ", err)
		return false
	}
	expDays, err := strconv.Atoi(days)
	cert, err := pki.SignCert(csr, 0, 0, expDays)
	if err != nil {
		log.Fatal("Sign cert failed: ", err)
		return false
	}

	workPath := path + userCertFilePath

	pki.DumpRSAKeytoFile(privateKey, workPath+cn+".key")
	pki.DumpCertificatetoPEMFile(cert, workPath+cn+".crt")

	cmd := exec.Command("zip", cn+".zip", cn+".crt", cn+".key" )
	cmd.Dir = workPath
	err = cmd.Run()
	if err != nil {
		log.Println(fmt.Sprint(err))
	}
	err = mail.SendMail(email, fmt.Sprintf(successNotifyMailTile, env, cn), fmt.Sprintf(successNotifyMailBody, cn), workPath+cn+".zip")
	if err != nil {
		log.Println(fmt.Sprint(err))
		return false
	}
	mailList := strings.Split(CONFIG.TeamMail, ";")
	for _, mailAddr := range mailList {
		err = mail.SendMail(mailAddr, fmt.Sprintf(successNotifyMailTile, env, cn), "ARCHIVED!", "")
		if err != nil {
			log.Println(err)
		}
	}
	return true
}