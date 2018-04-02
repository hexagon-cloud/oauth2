package oauth2

// ClientDetails interface for OAuth 2
type ClientDetails interface {
	GetID() string
	GetSecret() string
	GetDomain() string
	GetUserID() string
	GetScopes() []string
	GetAuthorizedGrantTypes() []GrantType
	GetAccessTokenValidSec() int32
	GetRefreshTokenValidSec() int32
}

// Client client model
type Client struct {
	ID                   string
	Secret               string
	Domain               string
	UserID               string
	Scopes               []string
	AuthorizedGrantTypes []GrantType
	AccessTokenValidSec  int32
	RefreshTokenValidSec int32
}

// GetID client id
func (c *Client) GetID() string {
	return c.ID
}

// GetSecret client domain
func (c *Client) GetSecret() string {
	return c.Secret
}

// GetDomain client domain
func (c *Client) GetDomain() string {
	return c.Domain
}

// GetUserID user id
func (c *Client) GetUserID() string {
	return c.UserID
}

// GetAuthorizedGrantTypes authorized grant types
func (c *Client) GetAuthorizedGrantTypes() []GrantType {
	return c.AuthorizedGrantTypes
}

// GetScopes scopes
func (c *Client) GetScopes() []string {
	return c.Scopes
}

// GetAccessTokenValidSec access token validity seconds
func (c *Client) GetAccessTokenValidSec() int32 {
	return c.AccessTokenValidSec
}

// GetRefreshTokenValidSec refresh validity seconds
func (c *Client) GetRefreshTokenValidSec() int32 {
	return c.RefreshTokenValidSec
}
