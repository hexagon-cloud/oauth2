package oauth2

// ResponseType the type of authorization request
type ResponseType string

// define the type of authorization request
const (
	CodeRsp  ResponseType = "code"
	TokenRsp ResponseType = "token"
)

func (rt ResponseType) String() string {
	if rt == CodeRsp ||
		rt == TokenRsp {
		return string(rt)
	}
	return ""
}

// GrantType authorization model
type GrantType string

// define authorization model
const (
	AuthorizationCode   GrantType = "authorization_code"
	PasswordCredentials GrantType = "password"
	ClientCredentials   GrantType = "client_credentials"
	RefreshToken        GrantType = "refresh_token"
	Implicit            GrantType = "implicit"
)

func (gt GrantType) String() string {
	if gt == AuthorizationCode ||
		gt == PasswordCredentials ||
		gt == ClientCredentials ||
		gt == RefreshToken {
		return string(gt)
	}
	return ""
}
