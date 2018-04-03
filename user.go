package oauth2

type UserDetails interface {
	GetAuthorities() []string
	GetUserID() string
	GetUsername() string
	GetPassword() string
	IsAccountNonExpired() bool
	IsAccountNonLocked() bool
	IsCredentialsNonExpired() bool
	IsEnabled() bool
}

// NewUser create to User model instance
func NewUser() *User {
	return &User{}
}

type User struct {
	UserID                string   `bson:"UserID"`
	Username              string   `bson:"Username"`
	Password              string   `bson:"Password"`
	AccountNonExpired     bool     `bson:"AccountNonExpired"`
	AccountNonLocked      bool     `bson:"AccountNonLocked"`
	CredentialsNonExpired bool     `bson:"CredentialsNonExpired"`
	Enabled               bool     `bson:"Enabled"`
	Authorities           []string `bson:"Authorities"`
}

func (u *User) GetAuthorities() []string {
	return u.Authorities
}

func (u *User) GetUserID() string {
	return u.UserID
}

func (u *User) GetUsername() string {
	return u.Username
}

func (u *User) GetPassword() string {
	return u.Password
}

func (u *User) IsAccountNonExpired() bool {
	return u.AccountNonExpired
}

func (u *User) IsAccountNonLocked() bool {
	return u.AccountNonLocked
}

func (u *User) IsCredentialsNonExpired() bool {
	return u.CredentialsNonExpired
}

func (u *User) IsEnabled() bool {
	return u.Enabled
}

// New create to User model instance
func (u *User) New() UserDetails {
	return NewUser()
}
