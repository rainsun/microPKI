package web

import (
	"fmt"
	"strings"
	"net/http"
	"log"
	"signCert/web/session"
	"signCert/utils"
)

const (
	sessionKeyENV = "ENV"
)

func indexController(w http.ResponseWriter, r *http.Request){
	session := sessionHandler(w, r)
	handleRequest(r)

	env := session.Get(sessionKeyENV).(string)
	cs := utils.GetCertsList(env)

	indexView(w, cs)
}

func certController(w http.ResponseWriter, r *http.Request){
	session := sessionHandler(w, r)
	handleRequest(r)
	if len(r.Form) == 0 || r.Form.Get("cert") == "" {
		fmt.Fprintf(w, "error")
		return
	}
	certFile := r.Form.Get("cert")
	env := session.Get(sessionKeyENV).(string)
	cert := utils.GetCertDetail(certFile, env)
	certDetailView(w, cert)
}

func signCertController(w http.ResponseWriter, r *http.Request)  {
	session := sessionHandler(w, r)
	r.ParseForm()
	handleRequest(r)
	env := session.Get(sessionKeyENV).(string)


	if len(r.Form) == 0 || r.Form.Get("cn") == "" || r.Form.Get("email") == "" {
		fmt.Fprintf(w, "error")
		return
	}
	cn := r.Form.Get("cn")
	email := r.Form.Get("email")
	days := ""
	if r.Form.Get("days") != "" {
		days = r.Form.Get("days")
	}
	if !strings.HasSuffix(email, "@we.com") {
		fmt.Fprintf(w, "please use corperation email address!")
		return
	}
	ret := utils.SignCert(cn, email, days, env)
	if ret {
		fmt.Fprintf(w, "Cert signed!")
	} else {
		fmt.Fprintf(w, "Cert sign failed!")
	}
}

func switchENVController(w http.ResponseWriter, r *http.Request)  {
	session := globalSessions.SessionStart(w, r)
	r.ParseForm()
	if r.Form.Get(sessionKeyENV) != ""{
		if (r.Form.Get(sessionKeyENV)) == utils.DevEnv || r.Form.Get(sessionKeyENV) == utils.ProdENV {
			session.Set(sessionKeyENV, r.Form.Get(sessionKeyENV))
			fmt.Fprintf(w, "OK")
		} else {
			fmt.Fprintf(w, "WRONG")
		}
	} else {
		fmt.Fprintf(w, "FAIL")
	}

}

func getENVController(w http.ResponseWriter, r *http.Request)  {
	session := globalSessions.SessionStart(w, r)
	fmt.Fprintf(w, session.Get(sessionKeyENV).(string))
}

func sessionHandler(w http.ResponseWriter, r *http.Request) session.Session  {
	session := globalSessions.SessionStart(w, r)
	if session.Get(sessionKeyENV) == nil {
		session.Set(sessionKeyENV, utils.DevEnv)
	}
	return session
}

func handleRequest(r *http.Request){
	r.ParseForm()
	log.Println("Get request from ", r.URL.Path, ", paramaters are ", r.Form)
	for k, v := range r.Form {
		fmt.Println("key:", k)
		fmt.Println("val:", strings.Join(v, ""))
	}
}