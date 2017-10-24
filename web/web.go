package web

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/spacemonkeygo/openssl"
	"io/ioutil"
	"log"
	"net/http"
	"signCert/web/session"
	"signCert/config"
)

var CONFIG config.WebConfig

func routeEngine() {
	http.HandleFunc("/", indexController) //设置访问的路由
	http.HandleFunc("/cert_detail", certController)
	http.HandleFunc("/cert_sign", signCertController)
	http.HandleFunc("/switch_env", switchENVController)
	http.HandleFunc("/get_env", getENVController)
}

var globalSessions *session.Manager

func MainLoop() {
	routeEngine()

	globalSessions, _ = session.NewManager("memory", "InfrCACookieId", 3600)
	go globalSessions.GC()

	server := &http.Server{Addr: CONFIG.Address + ":" + CONFIG.Listen}
	log.Println("Listen " + CONFIG.Address + ":" + CONFIG.Listen)
	var err error
	if CONFIG.EnableHttps {
		server.TLSConfig = generateTLSConfig()
		err = server.ListenAndServeTLS(CONFIG.ServerCertPath, CONFIG.ServerKeyPath)
	} else {
		err = server.ListenAndServe()

	}
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func generateTLSConfig() *tls.Config {
	config := &tls.Config{}
	if CONFIG.EnableHttps {
		config.InsecureSkipVerify = true
	}
	if CONFIG.EnableClientCertAuth {
		config.ClientAuth = tls.RequireAndVerifyClientCert

		rawCA, _ := ioutil.ReadFile(CONFIG.ClientAuthCAPath)
		crtPool := x509.NewCertPool()
		crtPool.AppendCertsFromPEM(rawCA)
		config.ClientCAs = crtPool
	}
	if CONFIG.EnableClientCertCNAuth {
		config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			hasAccess := false
			for _, rawCert := range rawCerts {
				certs, err := x509.ParseCertificates(rawCert)
				if err != nil {
					log.Fatal(err)
				}
				for _, cert := range certs {
					if cert.Subject.CommonName == CONFIG.AuthCN {
						hasAccess = true
					}
				}
			}
			if hasAccess {
				return nil
			} else {
				log.Fatal("Failed to auth by Cert!")
				return openssl.ValidationError
			}
		}
	}
	return config
}
