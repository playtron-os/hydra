package sessiontoken

import (
	"github.com/ory/hydra/v2/aead"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/hydra/v2/x"
)

type InternalRegistry interface {
	x.RegistryWriter
	x.RegistryLogger
	Registry
	client.ManagerProvider
}

type Registry interface {
	config.Provider
	KeyManager() jwk.Manager
	SoftwareKeyManager() jwk.Manager
	KeyCipher() *aead.AESGCM
}
