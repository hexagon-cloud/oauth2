package oauth2

import "time"

// ClientDetails interface for OAuth 2
type ClientDetails interface {
	GetID() string
	GetSecret() string
	GetDomain() string
	GetUserID() string
	GetScopes() []string
	GetAuthorizedGrantTypes() []GrantType
	GetAccessTokenExp() time.Duration
	GetRefreshTokenExp() time.Duration
}

// Client client model
type Client struct {
	ID                   string
	Secret               string
	Domain               string
	UserID               string
	Scopes               []string
	AuthorizedGrantTypes []GrantType
	AccessTokenExp       time.Duration
	RefreshTokenExp      time.Duration
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

// GetAccessTokenExp access token validity seconds
func (c *Client) GetAccessTokenExp() time.Duration {
	return c.AccessTokenExp
}

// GetRefreshTokenExp refresh validity seconds
func (c *Client) GetRefreshTokenExp() time.Duration {
	return c.RefreshTokenExp
}
