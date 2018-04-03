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
	GetClient(clientID string) (cli ClientDetails, err error)

	LoadUserByUsername(username string) (UserDetails, error)

	AuthenticateUser(username string, password string) (UserDetails, error)

	// generate the authorization token(code)
	GenerateAuthToken(rt ResponseType, tgr *TokenGenerateRequest, cli ClientDetails) (authToken TokenDetails, err error)

	// generate the access token
	GenerateAccessToken(rt GrantType, tgr *TokenGenerateRequest, cli ClientDetails) (accessToken TokenDetails, err error)

	// refreshing an access token
	RefreshAccessToken(tgr *TokenGenerateRequest) (accessToken TokenDetails, err error)

	// use the access token to delete the token information
	RemoveAccessToken(access string) (err error)

	// use the refresh token to delete the token information
	RemoveRefreshToken(refresh string) (err error)

	// according to the access token for corresponding token information
	LoadAccessToken(access string) (accessToken TokenDetails, err error)

	// according to the refresh token for corresponding token information
	LoadRefreshToken(refresh string) (refreshToken TokenDetails, err error)
}
