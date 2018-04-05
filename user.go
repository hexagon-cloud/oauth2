package oauth2

type User interface {
	GetAuthorities() []string
	GetUserID() string
	GetUsername() string
	GetPassword() string
	IsAccountNonExpired() bool
	IsAccountNonLocked() bool
	IsCredentialsNonExpired() bool
	IsEnabled() bool
}

// NewUser create to DefaultUser model instance
func NewUser() User {
	return &DefaultUser{}
}

type DefaultUser struct {
	UserID                string   `bson:"UserID"`
	Username              string   `bson:"Username"`
	Password              string   `bson:"Password"`
	AccountNonExpired     bool     `bson:"AccountNonExpired"`
	AccountNonLocked      bool     `bson:"AccountNonLocked"`
	CredentialsNonExpired bool     `bson:"CredentialsNonExpired"`
	Enabled               bool     `bson:"Enabled"`
	Authorities           []string `bson:"Authorities"`
}

func (u *DefaultUser) GetAuthorities() []string {
	return u.Authorities
}

func (u *DefaultUser) GetUserID() string {
	return u.UserID
}

func (u *DefaultUser) GetUsername() string {
	return u.Username
}

func (u *DefaultUser) GetPassword() string {
	return u.Password
}

func (u *DefaultUser) IsAccountNonExpired() bool {
	return u.AccountNonExpired
}

func (u *DefaultUser) IsAccountNonLocked() bool {
	return u.AccountNonLocked
}

func (u *DefaultUser) IsCredentialsNonExpired() bool {
	return u.CredentialsNonExpired
}

func (u *DefaultUser) IsEnabled() bool {
	return u.Enabled
}

// New create to DefaultUser model instance
func (u *DefaultUser) New() User {
	return NewUser()
}
