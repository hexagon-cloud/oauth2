package oauth2

type User interface {
	GetOpenid() string
	GetUsername() string
	GetPassword() string
}

// NewUser create to DefaultUser model instance
func NewUser() User {
	return &DefaultUser{}
}

type DefaultUser struct {
	Openid   string `json:"openid"`
	Username string `json:"username"`
	Password string `json:"-"`
}

func (u *DefaultUser) GetOpenid() string {
	return u.Openid
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
