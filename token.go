package oauth2

import (
	"time"
)

// Token the token information model interface
type Token interface {
	New() Token

	GetClientID() string
	SetClientID(string)
	GetUsername() string
	SetUsername(string)
	GetRedirectURI() string
	SetRedirectURI(string)
	GetScope() string
	SetScope(string)

	GetCode() string
	SetCode(string)
	GetCodeCreateAt() time.Time
	SetCodeCreateAt(time.Time)
	GetCodeExpiresIn() time.Duration
	SetCodeExpiresIn(time.Duration)

	GetAccess() string
	SetAccess(string)
	GetAccessCreateAt() time.Time
	SetAccessCreateAt(time.Time)
	GetAccessExpiresIn() time.Duration
	SetAccessExpiresIn(time.Duration)

	GetRefresh() string
	SetRefresh(string)
	GetRefreshCreateAt() time.Time
	SetRefreshCreateAt(time.Time)
	GetRefreshExpiresIn() time.Duration
	SetRefreshExpiresIn(time.Duration)
}

// NewToken create to token model instance
func NewToken() Token {
	return &DefaultToken{}
}

// DefaultToken token model
type DefaultToken struct {
	ClientID         string        `bson:"ClientID"`
	Username         string        `bson:"Username"`
	RedirectURI      string        `bson:"RedirectURI"`
	Scope            string        `bson:"Scope"`
	Code             string        `bson:"Code"`
	CodeCreateAt     time.Time     `bson:"CodeCreateAt"`
	CodeExpiresIn    time.Duration `bson:"CodeExpiresIn"`
	Access           string        `bson:"Access"`
	AccessCreateAt   time.Time     `bson:"AccessCreateAt"`
	AccessExpiresIn  time.Duration `bson:"AccessExpiresIn"`
	Refresh          string        `bson:"Refresh"`
	RefreshCreateAt  time.Time     `bson:"RefreshCreateAt"`
	RefreshExpiresIn time.Duration `bson:"RefreshExpiresIn"`
}

// New create to token model instance
func (t *DefaultToken) New() Token {
	return NewToken()
}

// GetClientID the client id
func (t *DefaultToken) GetClientID() string {
	return t.ClientID
}

// SetClientID the client id
func (t *DefaultToken) SetClientID(clientID string) {
	t.ClientID = clientID
}

// GetUsername the user id
func (t *DefaultToken) GetUsername() string {
	return t.Username
}

// SetUsername the user id
func (t *DefaultToken) SetUsername(userID string) {
	t.Username = userID
}

// GetRedirectURI redirect URI
func (t *DefaultToken) GetRedirectURI() string {
	return t.RedirectURI
}

// SetRedirectURI redirect URI
func (t *DefaultToken) SetRedirectURI(redirectURI string) {
	t.RedirectURI = redirectURI
}

// GetScope get scope of authorization
func (t *DefaultToken) GetScope() string {
	return t.Scope
}

// SetScope get scope of authorization
func (t *DefaultToken) SetScope(scope string) {
	t.Scope = scope
}

// GetCode authorization code
func (t *DefaultToken) GetCode() string {
	return t.Code
}

// SetCode authorization code
func (t *DefaultToken) SetCode(code string) {
	t.Code = code
}

// GetCodeCreateAt create Time
func (t *DefaultToken) GetCodeCreateAt() time.Time {
	return t.CodeCreateAt
}

// SetCodeCreateAt create Time
func (t *DefaultToken) SetCodeCreateAt(createAt time.Time) {
	t.CodeCreateAt = createAt
}

// GetCodeExpiresIn the lifetime in seconds of the authorization code
func (t *DefaultToken) GetCodeExpiresIn() time.Duration {
	return t.CodeExpiresIn
}

// SetCodeExpiresIn the lifetime in seconds of the authorization code
func (t *DefaultToken) SetCodeExpiresIn(exp time.Duration) {
	t.CodeExpiresIn = exp
}

// GetAccess access DefaultToken
func (t *DefaultToken) GetAccess() string {
	return t.Access
}

// SetAccess access DefaultToken
func (t *DefaultToken) SetAccess(access string) {
	t.Access = access
}

// GetAccessCreateAt create Time
func (t *DefaultToken) GetAccessCreateAt() time.Time {
	return t.AccessCreateAt
}

// SetAccessCreateAt create Time
func (t *DefaultToken) SetAccessCreateAt(createAt time.Time) {
	t.AccessCreateAt = createAt
}

// GetAccessExpiresIn the lifetime in seconds of the access token
func (t *DefaultToken) GetAccessExpiresIn() time.Duration {
	return t.AccessExpiresIn
}

// SetAccessExpiresIn the lifetime in seconds of the access token
func (t *DefaultToken) SetAccessExpiresIn(exp time.Duration) {
	t.AccessExpiresIn = exp
}

// GetRefresh refresh DefaultToken
func (t *DefaultToken) GetRefresh() string {
	return t.Refresh
}

// SetRefresh refresh DefaultToken
func (t *DefaultToken) SetRefresh(refresh string) {
	t.Refresh = refresh
}

// GetRefreshCreateAt create Time
func (t *DefaultToken) GetRefreshCreateAt() time.Time {
	return t.RefreshCreateAt
}

// SetRefreshCreateAt create Time
func (t *DefaultToken) SetRefreshCreateAt(createAt time.Time) {
	t.RefreshCreateAt = createAt
}

// GetRefreshExpiresIn the lifetime in seconds of the refresh token
func (t *DefaultToken) GetRefreshExpiresIn() time.Duration {
	return t.RefreshExpiresIn
}

// SetRefreshExpiresIn the lifetime in seconds of the refresh token
func (t *DefaultToken) SetRefreshExpiresIn(exp time.Duration) {
	t.RefreshExpiresIn = exp
}
