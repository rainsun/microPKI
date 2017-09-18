package main

import (
	"html/template"
	"net/http"
)


func indexView(w http.ResponseWriter, env string) {
	t := template.Must(template.ParseFiles("template/index.html"))
	cs := GetCertsList(env)
	t.Execute(w, cs)
}

func certDetailView(w http.ResponseWriter, certFileName string, env string) {
	t := template.Must(template.ParseFiles("template/cert_detail.html"))
	cert := GetCertDetail(certFileName, env)
	t.Execute(w, cert)
}
