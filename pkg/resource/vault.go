package resource

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/cloudfoundry-community/vaultkv"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v2"

	"github.com/QuoineFinancial/vault-resource/pkg/resource/models"
)

// Vault - the vault resource interface
type Vault interface {
	Check() []models.Version
	In() error
}

// Resource - the vault resource
type Resource struct {
	client   *vaultkv.Client
	logger   zerolog.Logger
	config   models.Request
	secrets  map[string]interface{}
	workDir  string
}

// New - returns a vault client for interaction with the vault API
func New(
	workDir string,
	config models.Request,
	logger zerolog.Logger,
) (*Resource, error) {
	var err error

	if config.Source.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		logger = logger.With().Caller().Logger()
	}

	config, err = validate(config)
	if err != nil {
		logger.Fatal().Err(err).
			Msg("error validating resource configuration")
	}

	vaultURL, err := url.Parse(config.Source.VaultAddr)
	if err != nil {
		logger.Fatal().Err(err).
			Msg("invalid vault_addr value")
	}

	c := vaultkv.Client{
		VaultURL: vaultURL,
		AuthToken: config.Source.VaultToken,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: config.Source.VaultInsecure,
				},
			},
		},
	}

	r := &Resource{
		client:  &c,
		config:  config,
		logger:  logger,
		workDir: workDir,
		secrets: make(map[string]interface{}, 0),
	}

	return r, nil
}

// Check - checks vault for new secret version
func (r Resource) Check() []models.Version {
	err := r.renewToken()
	if err != nil {
		r.logger.Fatal().AnErr("err", err).
			Msg("error occurred renewing token")
	}

	var versions []models.Version

	p := r.config.Source.VaultPath
	mount, v2, err := r.client.IsKVv2Mount(p)
	if v2 {
		_, path := vaultkv.SplitMount(p)
		metadata, err := r.client.V2GetMetadata(mount, path)
		if err != nil {
			r.logger.Fatal().AnErr("err", err).
				Msg("error occurred reading paths")
		}
		versions = append(versions, models.Version{
			Path: p,
			Version: fmt.Sprintf(
				"%v", metadata.CurrentVersion,
			),
		})
	} else {
		var data interface{}
		err = r.client.Get(p, &data)
		if err != nil {
			r.logger.Fatal().AnErr("err", err).
				Msg("error occurred reading paths")
		}
		h := sha256.New()
		_, err := h.Write([]byte(fmt.Sprintf("%s", data.(map[string]interface{}))))
		if err != nil {
			r.logger.Fatal().AnErr("err", err).
				Msg("error calculate hash for secret")
		}
		versions = append(versions, models.Version{
			Path:    p,
			Version: hex.EncodeToString(h.Sum(nil)),
		})
	}

	return versions
}

// In - executes the resource
func (r *Resource) In() error {
	err := r.renewToken()
	if err != nil {
		r.logger.Fatal().AnErr("err", err).
			Msg("error occurred renewing token")
	}

	err = r.read()
	if err != nil {
		r.logger.Fatal().Err(err).
			Msg("error reading secrets")
	}

	r.prefix()

	r.sanitize()

	r.upcase()

	err = r.format()
	if err != nil {
		r.logger.Fatal().Err(err).
			Msg("error formatting secrets")
	}

	return nil
}

// format - formats the output in either json or yaml
func (r Resource) format() error {
	var (
		b   []byte
		err error
	)

	switch f := strings.ToLower(r.config.Source.Format); f {
	case "json":
		b, err = json.Marshal(r.secrets)
		if err != nil {
			return err
		}

	case "yaml":
		b, err = yaml.Marshal(r.secrets)
		if err != nil {
			return err
		}

	default:
		b, err = json.Marshal(r.secrets)
		if err != nil {
			return err
		}
	}

	if len(b) <= 0 {
		return errors.New("no secrets found to write to file")
	}

	err = r.write(b)
	if err != nil {
		return err
	}

	return nil
}

// prefix - adds a custom prefix to each key
func (r *Resource) prefix() {
	if len(r.config.Source.Prefix) <= 0 {
		return
	}

	s := make(map[string]interface{}, 0)
	for k, v := range r.secrets {
		s[fmt.Sprintf("%s_%s", r.config.Source.Prefix, k)] = v
	}
	r.secrets = s
}

// read - reads vault for a secret at a given path
func (r *Resource) read() error {
	var (
		err    error
		data interface{}
	)

	p := r.config.Version.Path
	version, err := strconv.ParseUint(r.config.Version.Version, 10, 64)
	mount, v2, err := r.client.IsKVv2Mount(p)
	if v2 {
		_, subpath := vaultkv.SplitMount(p)
		_, err := r.client.V2Get(mount, subpath, &data, &vaultkv.V2GetOpts{Version: uint(version)})
		if err != nil {
			r.logger.Fatal().AnErr("err", err).
				Msg("error occurred reading paths")
		}
	} else {
		err = r.client.Get(p, &data)
		if err != nil {
			r.logger.Fatal().AnErr("err", err).
				Msg("error occurred reading paths")
		}
	}

	result := data.(map[string]interface{})
	if r.config.Source.Debug {
		var s []string
		for k := range result {
			s = append(s, k)
		}
		r.logger.Debug().Strs("secret_keys", s).
			Msg("secret(s) found, value(s) not shown")
	}

	r.secrets = result

	return nil
}

// sanitize - sanitizes keys converting dashes(-) and dots(.) to underscores
func (r *Resource) sanitize() {
	if !r.config.Source.Sanitize {
		return
	}

	s := make(map[string]interface{}, 0)
	for k, v := range r.secrets {
		k = strings.Replace(k, "-", "_", -1)
		k = strings.Replace(k, ".", "_", -1)
		s[k] = v
	}
	r.secrets = s
}

// upcase - converts keys to UPPERCASE
func (r *Resource) upcase() {
	if !r.config.Source.Upcase {
		return
	}

	s := make(map[string]interface{}, 0)
	for k, v := range r.secrets {
		s[strings.ToUpper(k)] = v
	}
	r.secrets = s
}

// write - writes the secrets to a file
func (r Resource) write(b []byte) error {
	f, err := os.OpenFile(
		fmt.Sprintf("%s/secrets", r.workDir),
		os.O_CREATE|os.O_WRONLY, 0644,
	)
	if err != nil {
		r.logger.Fatal().Err(err).
			Msg("error opening file for write")
	}
	defer f.Close()

	if _, err := f.Write(b); err != nil {
		r.logger.Fatal().Err(err).
			Msg("error writing to destination file")
	}

	return nil
}
