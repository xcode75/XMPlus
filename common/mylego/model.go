package mylego

type CertConfig struct {
	Provider         string            `mapstructure:"Provider"`
	Email            string            `mapstructure:"Email"`
	CertEnv          map[string]string `mapstructure:"CertEnv"`
}

type LegoCMD struct {
	C    *CertConfig
	path string
}
