package mylego

type CertConfig struct {
	Provider         string            `mapstructure:"Provider"`
	Email            string            `mapstructure:"Email"`
	CertEnv          map[string]string `mapstructure:"CertEnv"`
	CertFile         string            `mapstructure:"CertFile"`
	KeyFile          string            `mapstructure:"KeyFile"`	
}

type LegoCMD struct {
	C    *CertConfig
	path string
}
