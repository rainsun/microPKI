package config

type WebConfig struct {
	Address                string `yaml:"address"`
	Listen                 string `yaml:"listen"`
	EnableHttps            bool	  `yaml:"enable_https"`
	ServerCertPath         string `yaml:"server_cert_path"`
	ServerKeyPath          string `yaml:"server_key_path"`
	EnableClientCertAuth   bool   `yaml:"enable_client_cert_auth"`
	ClientAuthCAPath       string `yaml:"client_auth_ca_file_path"`
	EnableClientCertCNAuth bool   `yaml:"enable_client_cert_CN_auth"`
	AuthCN                 string `yaml:"auth_cn"`
}

type ConfigStruct struct {
	DevCAPath  string `yaml:"dev_ca_path"`
	ProdCAPath string `yaml:"prod_ca_path"`
	TeamMail   string `yaml:"team_mail_list"`
	WebConfig `yaml:"web"`
}
