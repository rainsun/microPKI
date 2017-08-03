package main

import (
	"os"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

type ConfigStruct struct {
	Address string
	Listen string
	DevCAPath string `yaml:"dev_ca_path"`
	ProdCAPath string `yaml:"prod_ca_path"`
	TeamMail string `yaml:"team_mail_list"`
}
var CONFIG = ConfigStruct{}

func main() {
	err := LoadConfig(&CONFIG)
	if err != nil {
		log.Panic(err)
		os.Exit(1)
	}
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
