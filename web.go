package main

import (
	"log"
	"net/http"
	"signCert/session"
)

func routeEngine(){
	http.HandleFunc("/", indexController) //设置访问的路由
	http.HandleFunc("/cert_detail", certController)
	http.HandleFunc("/cert_sign", signCertController)
	http.HandleFunc("/switch_env", switchENVController)
	http.HandleFunc("/get_env", getENVController)
}

var globalSessions *session.Manager

func MainLoop(){
	routeEngine()

	globalSessions, _ = session.NewManager("memory", "InfrCACookieId", 3600)
	go globalSessions.GC()

	server := &http.Server{
		Addr: CONFIG.Address + ":" + CONFIG.Listen,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
