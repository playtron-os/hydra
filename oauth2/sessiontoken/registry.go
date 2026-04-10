package sessiontoken

import (
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
)

type InternalRegistry interface {
	httpx.WriterProvider
	logrusx.Provider
	Registry
	client.ManagerProvider
}

type Registry interface {
	config.Provider
	KeyManager() jwk.Manager
}
