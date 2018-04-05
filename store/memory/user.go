package memory

import (
	"errors"
	"sync"

	"github.com/hexagon-cloud/oauth2"
)

// NewUserStore new UserStore using memory
func NewUserStore() *UserStore {
	return &UserStore{
		data: make(map[string]oauth2.User),
	}
}

// ClientStore client information store
type UserStore struct {
	sync.RWMutex
	data map[string]oauth2.User
}

func (us *UserStore) GetByUsername(username string) (user oauth2.User, err error) {
	us.RLock()
	defer us.RUnlock()
	if c, ok := us.data[username]; ok {
		user = c
		return
	}
	err = errors.New("not found")
	return
}

// Set set user information
func (us *UserStore) Set(username string, user oauth2.User) (err error) {
	us.Lock()
	defer us.Unlock()
	us.data[username] = user
	return
}
