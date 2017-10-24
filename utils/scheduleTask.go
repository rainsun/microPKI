package utils

import (
	"log"
	"io/ioutil"
	"strings"
	"signCert/microPKI"
	"time"
	"fmt"
	"signCert/mail"
)

const (
	SECONDS_PER_DAY      = 60 * 60 * 24
	ALERT_GUARDED_LEVEL  = 4
	ALERT_ELEVATED_LEVEL = 3
	ALERT_HIGH_LEVEL     = 2
	ALERT_SEVERE_LEVEL   = 1
	ALERT_IGNORE_LEVEL   = 0

	SUFFIX_CRT = "crt"
	SUFFIX_PEM = "pem"
)

var (
	notify_email_title = "[Inf Team] 证书即将过期 *%s*"
	notify_email_body  = "您的证书 [%s] 将在 %d 天后过期，请在这段时间内联系基础设施组，以免影响您的使用。 \n 请勿回复此邮件! \n 谢谢"

	ALERT_DURATION     = []int64{0, 7 * SECONDS_PER_DAY, 15 * SECONDS_PER_DAY, 30 * SECONDS_PER_DAY, 60 * SECONDS_PER_DAY}
	ALERT_LEVEL_STRING = []string{"忽略", "提醒", "重要", "警告", "紧急"}

	DEV_PKI microPKI.MicroPkI
	PROD_PKI microPKI.MicroPkI
)

func notAfterValidation(env string) {
	var path string = ""
	var pki microPKI.MicroPkI
	if env == ProdENV {
		path = CONFIG.ProdCAPath
		pki = PROD_PKI
	} else {
		path = CONFIG.DevCAPath
		pki = DEV_PKI
	}

	files, _ := ioutil.ReadDir(path + userCertFilePath)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), SUFFIX_CRT) || strings.HasSuffix(f.Name(), SUFFIX_PEM) {
			filePathName := path + userCertFilePath + f.Name()

			cert, err := microPKI.LoadCertificatefromPEMFile(filePathName)
			if err != nil {
				log.Fatal(filePathName, " parse failed!")
				continue
			}

			spread := cert.NotAfter.Unix() - time.Now().Unix()
			emailAddr := ""
			emailTitle := ""
			emailBody := ""
			if len(cert.Subject.Names) > 0 {
				for i := range cert.Subject.Names {
					if cert.Subject.Names[i].Type.Equal(microPKI.OidEmailAddress) {
						emailAddr = cert.Subject.Names[i].Value.(string)
					}
				}
			}

			alertLevel := -1
			for level := range ALERT_DURATION {
				if spread < ALERT_DURATION[level] {
					log.Println(filePathName, spread/SECONDS_PER_DAY, level, emailAddr)
					alertLevel = level
					emailTitle = fmt.Sprintf(notify_email_title, ALERT_LEVEL_STRING[level])
					emailBody = fmt.Sprintf(notify_email_body, cert.Subject.CommonName, spread/SECONDS_PER_DAY)
					break
				}
			}

			sendAble := pki.GetCertAlertAble(cert.Subject.CommonName, alertLevel)

			if alertLevel > 0 && sendAble {
				mail.SendMail(emailAddr, emailTitle, emailBody, "")
				for _, m := range strings.Split(CONFIG.TeamMail, ";") {
					log.Println(m)
					mail.SendMail(m, emailTitle, emailBody, "")
				}
				pki.SetCertAlertAble(cert.Subject.CommonName, alertLevel, false)
				if alertLevel-1 >= 0 {
					pki.SetCertAlertAble(cert.Subject.CommonName, alertLevel-1, true)
				}
			}
		}
	}
}

func DEVNotAfterValidationTask() {
	notAfterValidation(DevEnv)
}

func PRODNotAfterValidationTask() {
	notAfterValidation(ProdENV)
}
