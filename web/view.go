package web

import (
	"html/template"
	"net/http"
	"signCert/utils"
)


func indexView(w http.ResponseWriter, cs utils.Certs) {
	t := template.Must(template.ParseFiles("template/index.html"))
	t.Execute(w, cs)
}

func certDetailView(w http.ResponseWriter, cert string) {
	t := template.Must(template.ParseFiles("template/cert_detail.html"))
	t.Execute(w, cert)
}
