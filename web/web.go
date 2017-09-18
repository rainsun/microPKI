package web

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/spacemonkeygo/openssl"
	"io/ioutil"
	"log"
	"net/http"
	"signCert/web/session"
)

func routeEngine() {
	http.HandleFunc("/", indexController) //设置访问的路由
	http.HandleFunc("/cert_detail", certController)
	http.HandleFunc("/cert_sign", signCertController)
	http.HandleFunc("/switch_env", switchENVController)
	http.HandleFunc("/get_env", getENVController)
}

var globalSessions *session.Manager

func MainLoop(bindAddr string, port string, enableTLS bool, certPath string, certKey string, caCertPath string, enableClientCertAuth bool, enableClientCNAuth bool, authCN string) {
	routeEngine()

	globalSessions, _ = session.NewManager("memory", "InfrCACookieId", 3600)
	go globalSessions.GC()

	server := &http.Server{Addr: bindAddr + ":" + port}
	var err error
	if enableTLS {
		server.TLSConfig = generateTLSConfig(enableClientCertAuth, caCertPath, enableClientCNAuth, authCN)
		err = server.ListenAndServeTLS(certPath, certKey)
	} else {
		err = server.ListenAndServe()

	}
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
	log.Println("Listen " + bindAddr + ":" + port)
}

func generateTLSConfig(enableClientCertAuth bool, caCertPath string, enableClientCNAuth bool, authCN string) *tls.Config {
	config := &tls.Config{}
	config.InsecureSkipVerify = true
	if enableClientCertAuth {
		config.ClientAuth = tls.RequireAndVerifyClientCert

		rawCA, _ := ioutil.ReadFile(caCertPath)
		crtPool := x509.NewCertPool()
		crtPool.AppendCertsFromPEM(rawCA)
		config.ClientCAs = crtPool
	}
	if enableClientCNAuth {
		config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			hasAccess := false
			for _, rawCert := range rawCerts {
				certs, err := x509.ParseCertificates(rawCert)
				if err != nil {
					log.Fatal(err)
				}
				for _, cert := range certs {
					if cert.Subject.CommonName == authCN {
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
