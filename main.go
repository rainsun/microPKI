package main

import (
	"os"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"github.com/robfig/cron"
)

type ConfigStruct struct {
	Address string
	Listen string
	DevCAPath string `yaml:"dev_ca_path"`
	ProdCAPath string `yaml:"prod_ca_path"`
	TeamMail string `yaml:"team_mail_list"`
	EnableHttps bool `yaml:"enable_https"`
	ServerCertPath string `yaml:"server_cert_path"`
	ServerKeyPath string `yaml:"server_key_path"`
	EnableClientCertAuth bool `yaml:"enable_client_cert_auth"`
	ClientAuthCAPath string `yaml:"client_auth_ca_file_path"`
	EnableClientCertCNAuth bool `yaml:"enable_client_cert_CN_auth"`
	AuthCN string `yaml:"auth_cn"`
}
var CONFIG = ConfigStruct{}

func main() {
	err := LoadConfig(&CONFIG)
	if err != nil {
		log.Panic(err)
		os.Exit(1)
	}


	c := cron.New()
	//			秒 分 时 日 月 星期
	c.AddFunc("24 5 14 * * *", validateCertTask)
	c.Start()

	MainLoop()
	os.Exit(0)
}

func LoadConfig(config *ConfigStruct) error {
	configString, err := ioutil.ReadFile("config.yml")
	if err != nil {
		return err
	}
	yaml.Unmarshal(configString, config)
	return nil
}
