package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"signCert/config"
	"signCert/utils"
	"signCert/web"
	"signCert/microPKI"
	"github.com/robfig/cron"
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

	microPKI.DEV_PKI = *microPKI.NewMicroPKI_INTERNAL_PRIVATE_FUNCTION(CONFIG.DevCAPath + "/private/ca.cert", CONFIG.DevCAPath+"/private/ca.key", CONFIG.DevCAPath)
	microPKI.PROD_PKI = *microPKI.NewMicroPKI_INTERNAL_PRIVATE_FUNCTION(CONFIG.ProdCAPath + "/private/ca.cert", CONFIG.ProdCAPath+"/private/ca.key", CONFIG.ProdCAPath)

	c := cron.New()
	//			秒 分 时 日 月 星期
	c.AddFunc("@daily", utils.DEVNotAfterValidationTask)
	c.AddFunc("@daily", utils.PRODNotAfterValidationTask)
	c.Start()
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
