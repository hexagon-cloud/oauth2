package oauth2

// User user model interface
type User interface {
	GetID() uint64
	GetUsername() string
	GetPassword() string
}

// DefaultUser
type DefaultUser struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
}

func (u *DefaultUser) GetID() uint64 {
	return u.ID
}

func (u *DefaultUser) GetUsername() string {
	return u.Username
}

func (u *DefaultUser) GetPassword() string {
	return u.Password
}