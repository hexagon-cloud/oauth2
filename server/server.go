package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hexagon-cloud/oauth2"
)

// NewDefaultServer create a default authorization server
func NewDefaultServer(manager oauth2.Manager) *Server {
	return NewServer(NewConfig(), manager)
}

// NewServer create authorization server
func NewServer(cfg *Config, manager oauth2.Manager) *Server {
	if err := manager.CheckInterface(); err != nil {
		panic(err)
	}

	srv := &Server{
		Config:  cfg,
		Manager: manager,
	}

	// default handler
	srv.ClientInfoHandler = ClientBasicHandler

	srv.UserAuthorizationHandler = func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		err = oauth2.ErrAccessDenied
		return
	}

	return srv
}

// Server Provide authorization server
type Server struct {
	Config                   *Config
	Manager                  oauth2.Manager
	ClientInfoHandler        ClientInfoHandler
	UserAuthorizationHandler UserAuthorizationHandler
	ResponseErrorHandler     ResponseErrorHandler
	InternalErrorHandler     InternalErrorHandler
	ExtensionFieldsHandler   ExtensionFieldsHandler
}

func (s *Server) redirectError(w http.ResponseWriter, req *AuthorizeRequest, err error) (uerr error) {
	if req == nil {
		uerr = err
		return
	}
	data, _, _ := s.GetErrorData(err)
	err = s.redirect(w, req, data)
	return
}

func (s *Server) redirect(w http.ResponseWriter, req *AuthorizeRequest, data map[string]interface{}) (err error) {
	uri, err := s.GetRedirectURI(req, data)
	if err != nil {
		return
	}
	w.Header().Set("Location", uri)
	w.WriteHeader(302)
	return
}

func (s *Server) tokenError(w http.ResponseWriter, err error) (uerr error) {
	data, statusCode, header := s.GetErrorData(err)

	uerr = s.json(w, data, header, statusCode)
	return
}

func (s *Server) json(w http.ResponseWriter, data interface{}, header http.Header, statusCode ...int) (err error) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")

	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	status := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	w.WriteHeader(status)
	err = json.NewEncoder(w).Encode(data)
	return
}

// GetRedirectURI get redirect uri
func (s *Server) GetRedirectURI(req *AuthorizeRequest, data map[string]interface{}) (uri string, err error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return
	}

	q := u.Query()
	if req.State != "" {
		q.Set("state", req.State)
	}

	for k, v := range data {
		q.Set(k, fmt.Sprint(v))
	}

	switch req.ResponseType {
	case oauth2.CodeRsp:
		u.RawQuery = q.Encode()
	case oauth2.TokenRsp:
		u.RawQuery = ""
		u.Fragment, err = url.QueryUnescape(q.Encode())
		if err != nil {
			return
		}
	}

	uri = u.String()
	return
}

// CheckResponseType check allows response type
func (s *Server) CheckResponseType(rt oauth2.ResponseType) bool {
	for _, art := range s.Config.AllowedResponseTypes {
		if art == rt {
			return true
		}
	}
	return false
}

// ValidationAuthorizeRequest the authorization request validation
func (s *Server) ValidationAuthorizeRequest(r *http.Request) (req *AuthorizeRequest, err error) {
	redirectURI, err := url.QueryUnescape(r.FormValue("redirect_uri"))
	if err != nil {
		return
	}

	clientID := r.FormValue("client_id")
	if r.Method != "GET" ||
		clientID == "" ||
		redirectURI == "" {
		err = oauth2.ErrInvalidRequest
		return
	}

	resType := oauth2.ResponseType(r.FormValue("response_type"))

	if resType.String() == "" {
		err = oauth2.ErrUnsupportedResponseType
		return
	} else if allowed := s.CheckResponseType(resType); !allowed {
		err = oauth2.ErrUnauthorizedClient
		return
	}

	req = &AuthorizeRequest{
		RedirectURI:  redirectURI,
		ResponseType: resType,
		ClientID:     clientID,
		State:        r.FormValue("state"),
		Scope:        r.FormValue("scope"),
	}
	return
}

// ValidateClientGrantType check the client allows the grant type
func (s *Server) ValidateClientGrantType(gt oauth2.GrantType, cli oauth2.Client) bool {
	allowed := false
	for _, agt := range cli.GetGrantTypes() {
		if agt == gt {
			allowed = true
		}
	}
	return allowed
}

// ValidateClientScope check the client allows the authorized scope
func (s *Server) ValidateClientScope(scope string, cli oauth2.Client) bool {
	if scope == "" {
		return true
	}
	requestScopes := strings.Split(scope, ",")
	for _, rsp := range requestScopes {
		// contains
		allowed := false
		for _, sp := range cli.GetScopes() {
			if sp == rsp {
				allowed = true
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

// GetAuthorizeToken get authorization token(code)
func (s *Server) GetAuthorizeToken(req *AuthorizeRequest) (ti oauth2.Token, err error) {
	// load clientDetails
	client, err := s.Manager.GetClient(req.ClientID)
	if err != nil {
		err = oauth2.ErrInvalidClient
		return
	}
	gt := oauth2.AuthorizationCode
	if req.ResponseType == oauth2.TokenRsp {
		gt = oauth2.Implicit
	}

	grantTypeAllowed := s.ValidateClientGrantType(gt, client)
	if !grantTypeAllowed {
		err = oauth2.ErrUnsupportedGrantType
		return
	}

	requestScope := req.Scope
	if requestScope == "" {
		requestScope = strings.Join(client.GetScopes(), ",")
	} else {
		scopeAllowed := s.ValidateClientScope(requestScope, client)
		if !scopeAllowed {
			err = oauth2.ErrInvalidScope
			return
		}
	}

	tgr := &oauth2.TokenGenerateRequest{
		ClientID:       req.ClientID,
		UserID:         req.UserID,
		RedirectURI:    req.RedirectURI,
		Scope:          requestScope,
		AccessTokenExp: req.AccessTokenExp,
	}

	ti, err = s.Manager.GenerateAuthToken(req.ResponseType, tgr, client)
	return
}

// GetAuthorizeData get authorization response data
func (s *Server) GetAuthorizeData(rt oauth2.ResponseType, ti oauth2.Token) (data map[string]interface{}) {
	if rt == oauth2.CodeRsp {
		data = map[string]interface{}{
			"code": ti.GetCode(),
		}
	} else {
		data = s.GetTokenData(ti)
	}
	return
}

// HandleAuthorizeRequest the authorization request handling
func (s *Server) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) (err error) {
	req, verr := s.ValidationAuthorizeRequest(r)
	if verr != nil {
		err = s.redirectError(w, req, verr)
		return
	}

	// user authorization
	userID, verr := s.UserAuthorizationHandler(w, r)

	if verr != nil {
		err = s.redirectError(w, req, verr)
		return
	} else if userID == "" {
		return
	}

	req.UserID = userID

	ti, verr := s.GetAuthorizeToken(req)

	if verr != nil {
		err = s.redirectError(w, req, verr)
		return
	}

	err = s.redirect(w, req, s.GetAuthorizeData(req.ResponseType, ti))
	return
}

// ValidationTokenRequest the token request validation
func (s *Server) ValidationTokenRequest(r *http.Request) (gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest, client oauth2.Client, err error) {
	if v := r.Method; !(v == "POST" ||
		(s.Config.AllowGetAccessRequest && v == "GET")) {
		err = oauth2.ErrInvalidRequest
		return
	}

	gt = oauth2.GrantType(r.FormValue("grant_type"))

	if gt.String() == "" {
		err = oauth2.ErrInvalidRequest
		return
	}

	clientID, clientSecret, err := s.ClientInfoHandler(r)
	if err != nil {
		return
	}

	tgr = &oauth2.TokenGenerateRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	client, err = s.Manager.GetClient(tgr.ClientID)
	if err != nil {
		err = oauth2.ErrInvalidClient
		return
	} else if tgr.ClientSecret != client.GetSecret() {
		err = oauth2.ErrInvalidClient
		return
	}

	grantTypeAllowed := s.ValidateClientGrantType(gt, client)
	if !grantTypeAllowed {
		err = oauth2.ErrUnsupportedGrantType
		return
	}

	switch gt {
	case oauth2.AuthorizationCode:
		tgr.RedirectURI = r.FormValue("redirect_uri")
		tgr.Code = r.FormValue("code")

		if tgr.RedirectURI == "" ||
			tgr.Code == "" {
			err = oauth2.ErrInvalidRequest
			return
		}
	case oauth2.PasswordCredentials:
		tgr.Scope = r.FormValue("scope")
		username, password := r.FormValue("username"), r.FormValue("password")

		if username == "" || password == "" {
			err = oauth2.ErrInvalidRequest
			return
		}

		u, verr := s.Manager.AuthenticateUser(username, password)
		if verr != nil {
			err = verr
			return
		} else if u == nil {
			err = oauth2.ErrInvalidGrant
			return
		}

		tgr.UserID = u.GetUsername()
	case oauth2.ClientCredentials:
		tgr.Scope = r.FormValue("scope")
	case oauth2.RefreshToken:
		tgr.Refresh = r.FormValue("refresh_token")
		tgr.Scope = r.FormValue("scope")

		if tgr.Refresh == "" {
			err = oauth2.ErrInvalidRequest
		}
	}
	scopeAllowed := s.ValidateClientScope(tgr.Scope, client)
	if !scopeAllowed {
		err = oauth2.ErrInvalidScope
		return
	}
	if tgr.Scope == "" {
		tgr.Scope = strings.Join(client.GetScopes(), ",")
	}
	return
}

// CheckGrantType check allows grant type
func (s *Server) CheckGrantType(gt oauth2.GrantType) bool {
	for _, agt := range s.Config.AllowedGrantTypes {
		if agt == gt {
			return true
		}
	}
	return false
}

// GetAccessToken access token
func (s *Server) GetAccessToken(gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest, cli oauth2.Client) (ti oauth2.Token, err error) {
	if allowed := s.CheckGrantType(gt); !allowed {
		err = oauth2.ErrUnsupportedGrantType
		return
	}

	switch gt {
	case oauth2.AuthorizationCode:
		ati, verr := s.Manager.GenerateAccessToken(gt, tgr, cli)
		if verr != nil {

			if verr == oauth2.ErrInvalidAuthorizeCode {
				err = oauth2.ErrInvalidGrant
			} else if verr == oauth2.ErrInvalidClient {
				err = oauth2.ErrInvalidClient
			} else {
				err = verr
			}
			return
		}
		ti = ati
	case oauth2.PasswordCredentials, oauth2.ClientCredentials:
		ti, err = s.Manager.GenerateAccessToken(gt, tgr, cli)
	case oauth2.RefreshToken:
		rti, verr := s.Manager.LoadRefreshToken(tgr.Refresh)
		if verr != nil {
			if verr == oauth2.ErrInvalidRefreshToken || verr == oauth2.ErrExpiredRefreshToken {
				err = oauth2.ErrInvalidGrant
				return
			}
			err = verr
			return
		}

		rti, verr = s.Manager.RefreshAccessToken(tgr)
		if verr != nil {
			if verr == oauth2.ErrInvalidRefreshToken || verr == oauth2.ErrExpiredRefreshToken {
				err = oauth2.ErrInvalidGrant
			} else {
				err = verr
			}
			return
		}
		ti = rti
	}

	return
}

// GetTokenData token data
func (s *Server) GetTokenData(ti oauth2.Token) (data map[string]interface{}) {
	data = map[string]interface{}{
		"access_token": ti.GetAccess(),
		"token_type":   s.Config.TokenType,
		"expires_in":   int64(ti.GetAccessExpiresIn() / time.Second),
	}

	if scope := ti.GetScope(); scope != "" {
		data["scope"] = scope
	}

	if refresh := ti.GetRefresh(); refresh != "" {
		data["refresh_token"] = refresh
	}

	if fn := s.ExtensionFieldsHandler; fn != nil {
		ext := fn(ti)
		for k, v := range ext {
			if _, ok := data[k]; ok {
				continue
			}
			data[k] = v
		}
	}
	return
}

// HandleTokenRequest token request handling
func (s *Server) HandleTokenRequest(w http.ResponseWriter, r *http.Request) (err error) {
	gt, tgr, client, verr := s.ValidationTokenRequest(r)
	if verr != nil {
		err = s.tokenError(w, verr)
		return
	}

	ti, verr := s.GetAccessToken(gt, tgr, client)
	if verr != nil {
		err = s.tokenError(w, verr)
		return
	}

	err = s.json(w, s.GetTokenData(ti), nil)
	return
}

// HandleCheckTokenRequest check token request handling
func (s *Server) HandleCheckTokenRequest(w http.ResponseWriter, r *http.Request) (err error) {
	ac := r.FormValue("token")
	t, err := s.Manager.LoadAccessToken(ac)
	if err != nil {
		err = s.tokenError(w, err)
		return
	}
	data := map[string]interface{}{
		"client_id":  t.GetClientID(),
		"expires_in": int64(t.GetAccessExpiresIn() / time.Second),
	}
	if scope := t.GetScope(); len(scope) > 0 {
		data["scope"] = scope
	}
	if username := t.GetUsername(); len(username) > 0 {
		data["username"] = username
	}
	err = s.json(w, data, nil)
	return
}

// HandleTokenUserRequest get user info request handling
func (s *Server) HandleTokenUserRequest(w http.ResponseWriter, r *http.Request) (err error) {
	token, err := s.ValidationBearerToken(r)
	if err != nil {
		err = s.tokenError(w, err)
		return
	}
	u, err := s.Manager.LoadUserByUsername(token.GetUsername())
	if err != nil {
		err = s.tokenError(w, err)
		return
	}
	err = s.json(w, u, nil)
	return
}

// GetErrorData get error response data
func (s *Server) GetErrorData(err error) (data map[string]interface{}, statusCode int, header http.Header) {
	re := new(oauth2.ErrorResponse)

	if v, ok := oauth2.Descriptions[err]; ok {
		re.Error = err
		re.Description = v
		re.StatusCode = oauth2.StatusCodes[err]
	} else {
		if fn := s.InternalErrorHandler; fn != nil {
			if vre := fn(err); vre != nil {
				re = vre
			}
		}

		if re.Error == nil {
			re.Error = oauth2.ErrServerError
			re.Description = oauth2.Descriptions[oauth2.ErrServerError]
			re.StatusCode = oauth2.StatusCodes[oauth2.ErrServerError]
		}
	}

	if fn := s.ResponseErrorHandler; fn != nil {
		fn(re)

		if re == nil {
			re = new(oauth2.ErrorResponse)
		}
	}

	data = make(map[string]interface{})

	if err := re.Error; err != nil {
		data["error"] = err.Error()
	}

	if v := re.ErrorCode; v != 0 {
		data["error_code"] = v
	}

	if v := re.Description; v != "" {
		data["error_description"] = v
	}

	if v := re.URI; v != "" {
		data["error_uri"] = v
	}

	header = re.Header

	statusCode = http.StatusInternalServerError
	if v := re.StatusCode; v > 0 {
		statusCode = v
	}

	return
}

// BearerAuth parse bearer token
func (s *Server) BearerAuth(r *http.Request) (accessToken string, ok bool) {
	auth := r.Header.Get("Authorization")
	prefix := "Bearer "

	if auth != "" && strings.HasPrefix(auth, prefix) {
		accessToken = auth[len(prefix):]
	} else {
		accessToken = r.FormValue("access_token")
	}

	if accessToken != "" {
		ok = true
	}

	return
}

// ValidationBearerToken validation the bearer tokens
// https://tools.ietf.org/html/rfc6750
func (s *Server) ValidationBearerToken(r *http.Request) (token oauth2.Token, err error) {
	accessToken, ok := s.BearerAuth(r)
	if !ok {
		err = oauth2.ErrInvalidAccessToken
		return
	}

	token, err = s.Manager.LoadAccessToken(accessToken)

	return
}
