package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"signCert/config"
	"signCert/utils"
	"signCert/web"
)

var CONFIG = config.ConfigStruct{}

func main() {
	err := LoadConfig(&CONFIG)
	utils.CONFIG = CONFIG
	web.CONFIG = CONFIG.WebConfig
	if err != nil {
		log.Panic(err)
		os.Exit(1)
	}

	//c := cron.New()
	//			秒 分 时 日 月 星期
	//c.AddFunc("24 5 14 * * *", validateCertTask)
	//c.Start()

	web.MainLoop()
	os.Exit(0)
}

func LoadConfig(config *config.ConfigStruct) error {
	configString, err := ioutil.ReadFile("config.yml")
	if err != nil {
		return err
	}
	yaml.Unmarshal(configString, config)
	return nil
}
