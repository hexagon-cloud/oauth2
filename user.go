package oauth2

type User interface {
	GetID() string
	GetUsername() string
	GetPassword() string
}

// NewUser create to DefaultUser model instance
func NewUser() User {
	return &DefaultUser{}
}

type DefaultUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
}

func (u *DefaultUser) GetID() string {
	return u.ID
}

func (u *DefaultUser) GetUsername() string {
	return u.Username
}

func (u *DefaultUser) GetPassword() string {
	return u.Password
}

// New create to DefaultUser model instance
func (u *DefaultUser) New() User {
	return NewUser()
}
