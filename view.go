package main

import (
	"html/template"
	"net/http"
)


func indexView(w http.ResponseWriter, cs Certs) {
	t := template.Must(template.ParseFiles("template/index.html"))
	t.Execute(w, cs)
}

func certDetailView(w http.ResponseWriter, cert string) {
	t := template.Must(template.ParseFiles("template/cert_detail.html"))
	t.Execute(w, cert)
}
