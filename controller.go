package main

import (
	"fmt"
	"strings"
	"net/http"
	"log"
	"signCert/session"
)


func indexController(w http.ResponseWriter, r *http.Request){
	session := sessionHandler(w, r)
	r.ParseForm()  //解析参数，默认是不会解析的
	log.Println("Get request from ", r.URL.Path, ", paramaters are ", r.Form)
	for k, v := range r.Form {
		fmt.Println("key:", k)
		fmt.Println("val:", strings.Join(v, ""))
	}
	indexView(w, session.Get("ENV").(string))
}

func certController(w http.ResponseWriter, r *http.Request){
	session := sessionHandler(w, r)
	sess := globalSessions.SessionStart(w, r)
	log.Print(sess.Get("ENV"))
	r.ParseForm()
	log.Println("Get request from ", r.URL.Path, ", paramaters are ", r.Form)
	if len(r.Form) == 0 || r.Form.Get("cert") == "" {
		fmt.Fprintf(w, "error")
		return
	}
	certFile := r.Form.Get("cert")
	certDetailView(w, certFile, session.Get("ENV").(string))
}

func signCertController(w http.ResponseWriter, r *http.Request)  {
	session := sessionHandler(w, r)
	r.ParseForm()  //解析参数，默认是不会解析的
	log.Println("Get request from ", r.URL.Path, ", paramaters are ", r.Form)
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
	ret := SignCert(cn, email, days, session.Get("ENV").(string))
	if ret {
		fmt.Fprintf(w, "Cert signed!")
	} else {
		fmt.Fprintf(w, "Cert sign failed!")
	}
}

func switchENVController(w http.ResponseWriter, r *http.Request)  {
	session := globalSessions.SessionStart(w, r)
	r.ParseForm()
	if r.Form.Get("ENV") != ""{
		if (r.Form.Get("ENV")) == "DEV" || r.Form.Get("ENV") == "PROD" {
			session.Set("ENV", r.Form.Get("ENV"))
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
	fmt.Fprintf(w, session.Get("ENV").(string))
}

func sessionHandler(w http.ResponseWriter, r *http.Request) session.Session  {
	session := globalSessions.SessionStart(w, r)
	if session.Get("ENV") == nil {
		session.Set("ENV", "DEV")
	}
	return session
}