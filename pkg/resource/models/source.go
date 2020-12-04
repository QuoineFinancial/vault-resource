package models

// Source - source configuration for the resource
type Source struct {
	// VaultPath - the path to the secrets in vault.
	VaultPath string `json:"vault_path"`

	// Format - the desired output format. Supported formats are yaml or json.
	Format string `json:"format"`

	// Prefix - a desired prefix to prepend to a secret key.
	Prefix string `json:"prefix"`

	// VaultAddr - the address to the vault server.
	VaultAddr string `json:"vault_addr"`

	// VaultToken - the token to use to authenticate to vault.
	VaultToken string `json:"vault_token"`

	// Retries - the amount of times to try to read a secret from vault.
	Retries int `json:"retries"`

	// Debug - enable debug logging.
	Debug bool `json:"debug"`

	// Sanitize - convert dashes and dots to underscores in vault keys.
	Sanitize bool `json:"sanitize"`

	// Upcase - conver the vault keys to uppercase.
	Upcase bool `json:"upcase"`

	// VaultInsecure - connect the the vault server with insecure.
	VaultInsecure bool `json:"vault_insecure"`
}
