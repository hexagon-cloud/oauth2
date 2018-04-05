package server

import (
	"net/http"
	"time"

	"github.com/hexagon-cloud/oauth2"
)

type (
	// ClientInfoHandler get client info from request
	ClientInfoHandler func(r *http.Request) (clientID, clientSecret string, err error)

	// UserAuthorizationHandler get user id from request authorization
	UserAuthorizationHandler func(w http.ResponseWriter, r *http.Request) (userID string, err error)

	// RefreshingScopeHandler check the scope of the refreshing token
	RefreshingScopeHandler func(newScope, oldScope string) (allowed bool, err error)

	// ResponseErrorHandler response error handing
	ResponseErrorHandler func(re *oauth2.ErrorResponse)

	// InternalErrorHandler internal error handing
	InternalErrorHandler func(err error) (re *oauth2.ErrorResponse)

	// AuthorizeScopeHandler set the authorized scope
	AuthorizeScopeHandler func(w http.ResponseWriter, r *http.Request) (scope string, err error)

	// AccessTokenExpHandler set expiration date for the access token
	AccessTokenExpHandler func(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error)

	// ExtensionFieldsHandler in response to the access token with the extension of the field
	ExtensionFieldsHandler func(ti oauth2.Token) (fieldsValue map[string]interface{})
)

// ClientFormHandler get client data from form
func ClientFormHandler(r *http.Request) (clientID, clientSecret string, err error) {
	clientID = r.Form.Get("client_id")
	clientSecret = r.Form.Get("client_secret")
	if clientID == "" || clientSecret == "" {
		err = oauth2.ErrInvalidClient
	}
	return
}

// ClientBasicHandler get client data from basic authorization
func ClientBasicHandler(r *http.Request) (clientID, clientSecret string, err error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		err = oauth2.ErrInvalidClient
		return
	}
	clientID = username
	clientSecret = password
	return
}
