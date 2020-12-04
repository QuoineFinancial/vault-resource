package resource

func (r *Resource) renewToken() error {
	r.logger.Debug().Msg("attempting renewal of token")

	err := r.client.TokenRenewSelf()
	if err != nil {
		return err
	}

	r.logger.Debug().Msg("successfully renewal of token")
	return nil
}
