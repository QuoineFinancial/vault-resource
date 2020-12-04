package main

import (
	"encoding/json"
	"os"

	"github.com/rs/zerolog"

	"github.com/QuoineFinancial/vault-resource/pkg/resource"
	"github.com/QuoineFinancial/vault-resource/pkg/resource/models"
)

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()

	zerolog.TimeFieldFormat = ""
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	var request models.Request
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		logger.Fatal().Err(err).
			Msg("error reading from stdin")
	}

	response := models.Response{
		Metadata: nil,
		Version: models.Version{
			Path: request.Version.Path,
			Version: request.Version.Version,
		},
	}

	// first argument on stdin is the working directory
	vault, err := resource.New(os.Args[1], request, logger)
	if err != nil {
		logger.Fatal().Err(err).
			Msg("error creating resource client")
	}

	err = vault.In()
	if err != nil {
		logger.Fatal().Err(err).
			Msg("error running file for write")
	}

	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		logger.Fatal().Err(err).
			Msg("writing response")
	}
}
