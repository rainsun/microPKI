package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"bytes"
	"fmt"
	"signCert/mail"
)

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

	files, _ := ioutil.ReadDir(path + "/users/")
	for _, f := range files {
		if strings.HasSuffix(f.Name(), "crt") || strings.HasSuffix(f.Name(), "pem") {
			certFile, _ := ioutil.ReadFile(path + "/users/" + f.Name())
			pemBlock, _ := pem.Decode(certFile)
			if pemBlock == nil {
				continue
			}
			if pemBlock.Type != "CERTIFICATE" || len(pemBlock.Headers) != 0 {
				continue
			}

			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				log.Fatal(f.Name(), err)
				continue
			}
			// C = CN, ST = Beijing, L = Haidian, O = Renrendai, OU = InfTeam
			// C = CN, ST = Beijing, O = Renrendai, OU = InfTeam, L = Haidian, CN = HuangDaowei, emailAddress = huangdaowei@we.com
			if len(cert.Subject.CommonName) == 0 {
				continue
			}
			c := Cert{Filename: f.Name(), Subject: getDNfromPkiName(cert.Subject), Exp: cert.NotAfter.Format("2006-01-02 15:04:05"), Issuer: getDNfromPkiName(cert.Issuer)}
			cs.Crt = append(cs.Crt, c)
		}
	}
	return cs
}

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
		subject += "C = " + c + ", "
	}
	for _, st := range name.StreetAddress {
		subject += "ST = " + st + ", "
	}
	for _, l := range name.Locality {
		subject += "L = " + l + ", "
	}
	for _, o := range name.Organization {
		subject += "O = " + o + ", "
	}
	for _, ou := range name.OrganizationalUnit {
		subject += "OU = " + ou + ", "
	}
	subject += "CN = " + name.CommonName
	return subject
}

func GeneratePrivateKey(cn string, env string) interface{} {
	var path string =""

	if env == "PROD" {
		path = CONFIG.ProdCAPath
	} else {
		path = CONFIG.DevCAPath
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %s", err)
	}
	privKeyFile, err := os.OpenFile(path+"/users/"+cn+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(privKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	privKeyFile.Close()
	return priv
}

func GenerateCertRequest(cn string, email string) bool {
	cmd := exec.Command("openssl", "req", "-new", "-key", CONFIG.DevCAPath+"users/"+cn+".key", "-out", CONFIG.DevCAPath+"users/"+cn+".csr",
	"-subj", `/C=CN/ST=Beijing/O=Renrendai/OU=InfTeam/L=Haidian/CN=`+cn+`/emailAddress=`+email)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Println(fmt.Sprint(err) + ": " + stderr.String())
		return false
	}
	return true
}

func SignCert(cn string, email string, days string, env string) bool {
	var path string =""

	if env == "PROD" {
		path = CONFIG.ProdCAPath
	} else {
		path = CONFIG.DevCAPath
	}

	GeneratePrivateKey(cn, env)
	ret := GenerateCertRequest(cn, email)
	if !ret {
		return false
	}
	//openssl ca -in server/server.csr -cert private/ca.crt -keyfile private/ca.key -out server/server.crt -config "./conf/openssl.conf"
	var cmd *exec.Cmd
	if days != "" {
		cmd = exec.Command("openssl", "ca", "-in", "users/"+cn+".csr",
			"-cert", "private/ca.crt", "-out", "users/"+cn+".crt",
			"-config", "conf/openssl.conf", "-batch",
			"-days", days,
		)
	} else {
		cmd = exec.Command("openssl", "ca", "-in", "users/"+cn+".csr",
			"-cert", "private/ca.crt", "-out", "users/"+cn+".crt",
			"-config", "conf/openssl.conf", "-batch")
	}
	cmd.Dir = path
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Println(fmt.Sprint(err) + ": " + stderr.String())
		return false
	}

	cmd = exec.Command("zip", cn+".zip", cn+".crt", cn+".key" )
	cmd.Dir = path + "/users"
	err = cmd.Run()
	if err != nil {
		log.Println(fmt.Sprint(err))
	}
	err = mail.SendMail(email, "[INFR PKI] ["+env+"] Cert signed for " + cn, cn+"'s cert has been signed!\n Please download attachment as archive of the cert!", path+"/users/"+cn+".zip")
	if err != nil {
		log.Println(fmt.Sprint(err))
		return false
	}
	mailList := strings.Split(CONFIG.TeamMail, ";")
	for _, mailAddr := range mailList {
		err = mail.SendMail(mailAddr, "[INFR PKI] ["+env+"] Cert signed for " + cn, "ARCHIVED!", "")
		if err != nil {
			log.Println(err)
		}
	}
	return true
}
