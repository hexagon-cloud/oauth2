package memory

import (
	"errors"
	"sync"

	"github.com/hexagon-cloud/oauth2"
)

// NewClientStore new ClientStore using memory
func NewClientStore() *ClientStore {
	return &ClientStore{
		data: make(map[string]oauth2.ClientDetails),
	}
}

// ClientStore client information store
type ClientStore struct {
	sync.RWMutex
	data map[string]oauth2.ClientDetails
}

// GetByID according to the ID for the client information
func (cs *ClientStore) GetByID(id string) (cli oauth2.ClientDetails, err error) {
	cs.RLock()
	defer cs.RUnlock()
	if c, ok := cs.data[id]; ok {
		cli = c
		return
	}
	err = errors.New("not found")
	return
}

// Set set client information
func (cs *ClientStore) Set(id string, cli oauth2.ClientDetails) (err error) {
	cs.Lock()
	defer cs.Unlock()
	cs.data[id] = cli
	return
}
