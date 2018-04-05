package oauth2

type (
	// ClientStore the client information storage interface
	ClientStore interface {
		// according to the ID for the client information
		GetByID(id string) (Client, error)
	}

	// TokenStore the token information storage interface
	TokenStore interface {
		// create and store the new token information
		Create(token Token) error

		// delete the authorization code
		RemoveByCode(code string) error

		// use the access token to delete the token information
		RemoveByAccess(access string) error

		// use the refresh token to delete the token information
		RemoveByRefresh(refresh string) error

		// use the authorization code for token information data
		GetByCode(code string) (Token, error)

		// use the access token for token information data
		GetByAccess(access string) (Token, error)

		// use the refresh token for token information data
		GetByRefresh(refresh string) (Token, error)
	}

	// UserStore the user information storage interface
	UserStore interface {
		GetByUsername(username string) (User, error)
	}
)
