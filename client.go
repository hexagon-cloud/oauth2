package oauth2

import "time"

// Client interface for OAuth 2
type Client interface {
	GetID() string
	GetSecret() string
	GetRedirectUri() string
	GetScopes() []string
	GetGrantTypes() []GrantType
	GetAccessTokenExp() time.Duration
	GetRefreshTokenExp() time.Duration
}

// DefaultClient s a simple default implementation of the Client interface.
type DefaultClient struct {
	ID              string
	Secret          string
	RedirectUri     string
	Scopes          []string
	GrantTypes      []GrantType
	AccessTokenExp  time.Duration
	RefreshTokenExp time.Duration
}

// GetID client id
func (c *DefaultClient) GetID() string {
	return c.ID
}

// GetSecret client domain
func (c *DefaultClient) GetSecret() string {
	return c.Secret
}

// GetRedirectUri client domain
func (c *DefaultClient) GetRedirectUri() string {
	return c.RedirectUri
}

// GetGrantTypes authorized grant types
func (c *DefaultClient) GetGrantTypes() []GrantType {
	return c.GrantTypes
}

// GetScopes scopes
func (c *DefaultClient) GetScopes() []string {
	return c.Scopes
}

// GetAccessTokenExp access token validity seconds
func (c *DefaultClient) GetAccessTokenExp() time.Duration {
	return c.AccessTokenExp
}

// GetRefreshTokenExp refresh validity seconds
func (c *DefaultClient) GetRefreshTokenExp() time.Duration {
	return c.RefreshTokenExp
}
