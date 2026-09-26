package logmanager

// StorageCreds per storage type — encrypted JSON before persisting.

type S3Creds struct {
	Endpoint   string `json:"endpoint"`
	Protocol   string `json:"protocol"`
	AccessKey  string `json:"access_key"`
	SecretKey  string `json:"secret_key"`
	Bucket     string `json:"bucket"`
	Region     string `json:"region"`
	PathPrefix string `json:"path_prefix"`
}

type GCSCreds struct {
	Bucket          string `json:"bucket"`
	CredentialsJSON string `json:"credentials_json"` // service-account JSON string
	PathPrefix      string `json:"path_prefix"`
}

type AzureCreds struct {
	AccountName string `json:"account_name"`
	AccountKey  string `json:"account_key"`
	Container   string `json:"container"`
	PathPrefix  string `json:"path_prefix"`
}

type SFTPCreds struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	RemotePath string `json:"remote_path"`
}

type NFSCreds struct {
	MountPath  string `json:"mount_path"`
	PathPrefix string `json:"path_prefix"`
}

type ElasticsearchCreds struct {
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	APIKey      string `json:"api_key"`
	IndexPrefix string `json:"index_prefix"`
}

type SIEMCreds struct {
	URL    string `json:"url"`
	Token  string `json:"token"`
	Format string `json:"format"` // "json", "cef"
}
