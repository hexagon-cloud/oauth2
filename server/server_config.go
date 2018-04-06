package server

import (
	"github.com/hexagon-cloud/oauth2"
)

// SetTokenType token type
func (s *Server) SetTokenType(tokenType string) {
	s.Config.TokenType = tokenType
}

// SetAllowGetAccessRequest to allow GET requests for the token
func (s *Server) SetAllowGetAccessRequest(allow bool) {
	s.Config.AllowGetAccessRequest = allow
}

// SetAllowedResponseType allow the authorization types
func (s *Server) SetAllowedResponseType(types ...oauth2.ResponseType) {
	s.Config.AllowedResponseTypes = types
}

// SetAllowedGrantType allow the grant types
func (s *Server) SetAllowedGrantType(types ...oauth2.GrantType) {
	s.Config.AllowedGrantTypes = types
}

// SetClientInfoHandler get client info from request
func (s *Server) SetClientInfoHandler(handler ClientInfoHandler) {
	s.ClientInfoHandler = handler
}

// SetClientAuthorizedHandler check the client allows to use this authorization grant type
// func (s *Server) SetClientAuthorizedHandler(handler ClientAuthorizedHandler) {
// 	s.ClientAuthorizedHandler = handler
// }

// // SetClientScopeHandler check the client allows to use scope
// func (s *Server) SetClientScopeHandler(handler ClientScopeHandler) {
// 	s.ClientScopeHandler = handler
// }

// SetUserAuthorizationHandler get user id from request authorization
func (s *Server) SetUserAuthorizationHandler(handler UserAuthorizationHandler) {
	s.UserAuthorizationHandler = handler
}

// SetResponseErrorHandler response error handling
func (s *Server) SetResponseErrorHandler(handler ResponseErrorHandler) {
	s.ResponseErrorHandler = handler
}

// SetInternalErrorHandler internal error handling
func (s *Server) SetInternalErrorHandler(handler InternalErrorHandler) {
	s.InternalErrorHandler = handler
}

// SetExtensionFieldsHandler in response to the access token with the extension of the field
func (s *Server) SetExtensionFieldsHandler(handler ExtensionFieldsHandler) {
	s.ExtensionFieldsHandler = handler
}

