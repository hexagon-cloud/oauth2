package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gavv/httpexpect"
	"github.com/hexagon-cloud/oauth2"
	mgr "github.com/hexagon-cloud/oauth2/manager"
	buntdbStore "github.com/hexagon-cloud/oauth2/store/buntdb"
	memoryStore "github.com/hexagon-cloud/oauth2/store/memory"
	"github.com/hexagon-cloud/oauth2/password/hmac"
)

var (
	srv          *Server
	tsrv         *httptest.Server
	manager      *mgr.Manager
	csrv         *httptest.Server
	clientID     = "app"
	clientSecret = "app"
	scopes       = []string{"server", "all"}
	grantType    = []oauth2.GrantType{oauth2.ClientCredentials, oauth2.PasswordCredentials, oauth2.AuthorizationCode}
)

func init() {
	manager = mgr.NewDefaultManager()
	manager.MustTokenStorage(buntdbStore.NewMemoryTokenStore())
}

func clientStore(redirectUri string) oauth2.ClientStore {
	clientStore := memoryStore.NewClientStore()
	clientStore.Set(clientID, &oauth2.DefaultClient{
		ID:          clientID,
		Secret:      clientSecret,
		RedirectUri: redirectUri,
		Scopes:      scopes,
		GrantTypes:  grantType,
	})
	return clientStore
}

func testServer(t *testing.T, w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/authorize":
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	case "/token":
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	case "check_token":
		err := srv.HandleCheckTokenRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	case "user_info":
		err := srv.HandleUserInfoRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestAuthorizeCode(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL))
	srv = NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", url.QueryEscape(csrv.URL+"/oauth2")).
		Expect().Status(http.StatusOK)
}

func TestImplicit(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, _ := r.Form.Get("code"), r.Form.Get("state")
			//if state != "123" {
			//	t.Error("unrecognized state:", state)
			//	return
			//}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL))
	srv = NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "json").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", url.QueryEscape(csrv.URL+"/oauth2")).
		Expect().Status(http.StatusOK)
}

func TestPasswordCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore(""))
	// password encoder
	pwdEncoder := hmac.NewPasswordEncoder("key")
	manager.MapPasswordEncoder(pwdEncoder)

	// user store
	userStore := memoryStore.NewUserStore()
	userStore.Set("user1", &oauth2.DefaultUser{
		Username: "user1",
		Password: pwdEncoder.Encode("pwd1"),
	})
	manager.MapUserStorage(userStore)
	srv = NewDefaultServer(manager)

	resObj := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "user1").
		WithFormField("password", "pwd1").
		WithFormField("scope", "all").
		WithBasicAuth(clientID, clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw())
	usrObj := e.GET("/user_info").
		WithHeader("Authorization",
		"Bearer "+resObj.Value("access_token").String().Raw()).
		Expect().Status(http.StatusOK).JSON().Object()

	t.Logf("%#v\n", usrObj.Raw())
}

func TestClientCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore(""))

	srv = NewDefaultServer(manager)
	srv.SetClientInfoHandler(ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *oauth2.ErrorResponse) {
		t.Log("OAuth 2.0 Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *oauth2.ErrorResponse) {
		t.Log("ErrorResponse Error:", re.Error)
	})

	srv.SetAllowedGrantType(oauth2.ClientCredentials)
	srv.SetAllowGetAccessRequest(false)
	srv.SetExtensionFieldsHandler(func(ti oauth2.Token) (fieldsValue map[string]interface{}) {
		fieldsValue = map[string]interface{}{
			"extension": "param",
		}
		return
	})
	srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "client_credentials").
		WithFormField("scope", "all").
		WithFormField("client_id", clientID).
		WithFormField("client_secret", clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw())
}

func TestRefreshing(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			jresObj := e.POST("/json").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", jresObj.Raw())

			validationAccessToken(t, jresObj.Value("access_token").String().Raw())

			resObj := e.POST("/json").
				WithFormField("grant_type", "refresh_token").
				WithFormField("scope", "one").
				WithFormField("refresh_token", jresObj.Value("refresh_token").String().Raw()).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL))
	srv = NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", url.QueryEscape(csrv.URL+"/oauth2")).
		Expect().Status(http.StatusOK)
}

// validation access json
func validationAccessToken(t *testing.T, accessToken string) {
	req := httptest.NewRequest("GET", "http://example.com", nil)

	req.Header.Set("Authorization", "Bearer "+accessToken)

	ti, err := srv.ValidationBearerToken(req)
	if err != nil {
		t.Error(err.Error())
		return
	}
	if ti.GetClientID() != clientID {
		t.Error("invalid access json")
	}
}
