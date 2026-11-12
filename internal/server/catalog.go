package server

import (
	"github.com/qdm12/gluetun/internal/control/catalog"
	"github.com/qdm12/gluetun/internal/models"
)

type storageCatalogSource struct {
	storage  Storage
	provider string
}

func (s storageCatalogSource) Servers() ([]models.Server, error) {
	return s.storage.GetServers(s.provider), nil
}

func newCatalog(storage Storage, provider string) *catalog.Catalog {
	return catalog.New(storageCatalogSource{storage: storage, provider: provider})
}
