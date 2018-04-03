package oauth2

import (
	"errors"
	"net/http"
)

// ErrorResponse error response
type ErrorResponse struct {
	Error       error
	ErrorCode   int
	Description string
	URI         string
	StatusCode  int
	Header      http.Header
}

// NewErrorResponse create the response pointer
func NewErrorResponse(err error, statusCode int) *ErrorResponse {
	return &ErrorResponse{
		Error:      err,
		StatusCode: statusCode,
	}
}

// SetHeader sets the header entries associated with key to
// the single element value.
func (r *ErrorResponse) SetHeader(key, value string) {
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Set(key, value)
}

// https://tools.ietf.org/html/rfc6749#section-5.2
var (
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrInvalidClient           = errors.New("invalid_client")
	ErrInvalidGrant            = errors.New("invalid_grant")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrUnsupportedGrantType    = errors.New("unsupported_grant_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrAccessDenied            = errors.New("access_denied")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrServerError             = errors.New("server_error")
	ErrTemporarilyUnavailable  = errors.New("temporarily_unavailable")
)

// Descriptions error description
var Descriptions = map[error]string{
	ErrInvalidRequest:          "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed",
	ErrInvalidClient:           "Client authentication failed",
	ErrInvalidGrant:            "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client",
	ErrUnauthorizedClient:      "The client is not authorized to request an authorization code using this method",
	ErrUnsupportedGrantType:    "The authorization grant type is not supported by the authorization server",
	ErrInvalidScope:            "The requested scope is invalid, unknown, or malformed",
	ErrAccessDenied:            "The resource owner or authorization server denied the request",
	ErrUnsupportedResponseType: "The authorization server does not support obtaining an authorization code using this method",
	ErrServerError:             "The authorization server encountered an unexpected condition that prevented it from fulfilling the request",
	ErrTemporarilyUnavailable:  "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server",
}

// StatusCodes response error HTTP status code
var StatusCodes = map[error]int{
	ErrInvalidRequest:          400,
	ErrInvalidClient:           401,
	ErrInvalidGrant:            401,
	ErrUnauthorizedClient:      401,
	ErrUnsupportedGrantType:    401,
	ErrInvalidScope:            400,
	ErrAccessDenied:            403,
	ErrUnsupportedResponseType: 401,
	ErrServerError:             500,
	ErrTemporarilyUnavailable:  503,
}
