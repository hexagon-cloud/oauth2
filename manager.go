package oauth2

import (
	"time"
)

// TokenGenerateRequest provide to generate the token request parameters
type TokenGenerateRequest struct {
	ClientID       string
	ClientSecret   string
	UserID         string
	RedirectURI    string
	Scope          string
	Code           string
	Refresh        string
	AccessTokenExp time.Duration
}

// Manager authorization management interface
type Manager interface {
	// check the interface implementation
	CheckInterface() (err error)

	// get the client information
	GetClient(clientID string) (cli Client, err error)

	LoadUserByUsername(username string) (User, error)

	AuthenticateUser(username string, password string) (User, error)

	// generate the authorization token(code)
	GenerateAuthToken(rt ResponseType, tgr *TokenGenerateRequest, cli Client) (authToken Token, err error)

	// generate the access token
	GenerateAccessToken(rt GrantType, tgr *TokenGenerateRequest, cli Client) (accessToken Token, err error)

	// refreshing an access token
	RefreshAccessToken(tgr *TokenGenerateRequest) (accessToken Token, err error)

	// use the access token to delete the token information
	RemoveAccessToken(access string) (err error)

	// use the refresh token to delete the token information
	RemoveRefreshToken(refresh string) (err error)

	// according to the access token for corresponding token information
	LoadAccessToken(access string) (accessToken Token, err error)

	// according to the refresh token for corresponding token information
	LoadRefreshToken(refresh string) (refreshToken Token, err error)
}
