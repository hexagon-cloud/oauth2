package manager

import (
	"time"

	"github.com/codegangsta/inject"
	"github.com/hexagon-cloud/oauth2"
	"github.com/hexagon-cloud/oauth2/generates"
)

// NewDefaultManager create to default authorization management instance
func NewDefaultManager() *Manager {
	m := NewManager()
	// default implementation
	m.MapTokenModel(oauth2.NewToken())
	m.MapAuthorizeGenerate(generates.NewAuthorizeGenerate())
	m.MapAccessGenerate(generates.NewAccessGenerate())

	return m
}

// NewManager create to authorization management instance
func NewManager() *Manager {
	return &Manager{
		injector:    inject.New(),
		gtcfg:       make(map[oauth2.GrantType]*Config),
		validateURI: DefaultValidateURI,
	}
}

// Manager provide authorization management
type Manager struct {
	injector    inject.Injector
	codeExp     time.Duration
	gtcfg       map[oauth2.GrantType]*Config
	rcfg        *RefreshingConfig
	validateURI ValidateURIHandler
}

func (m *Manager) AuthenticateUser(username string, password string) (user oauth2.User, err error) {
	m.injector.Invoke(func(us oauth2.UserStore, encoder oauth2.PasswordEncoder) {
		user, err = us.GetByUsername(username)
		if err != nil {
			err = oauth2.ErrInvalidGrant
			return
		}
		if !encoder.Matches(password, user.GetPassword()) {
			err = oauth2.ErrInvalidGrant
			return
		}
	})
	return
}

func (m *Manager) LoadUserByUsername(username string) (user oauth2.User, err error) {
	m.injector.Invoke(func(us oauth2.UserStore) {
		user, err = us.GetByUsername(username)
	})
	return
}

// get grant type config
func (m *Manager) grantConfig(gt oauth2.GrantType) *Config {
	if c, ok := m.gtcfg[gt]; ok && c != nil {
		return c
	}
	switch gt {
	case oauth2.AuthorizationCode:
		return DefaultAuthorizeCodeTokenCfg
	case oauth2.Implicit:
		return DefaultImplicitTokenCfg
	case oauth2.PasswordCredentials:
		return DefaultPasswordTokenCfg
	case oauth2.ClientCredentials:
		return DefaultClientTokenCfg
	}
	return &Config{}
}

// SetAuthorizeCodeExp set the authorization code expiration time
func (m *Manager) SetAuthorizeCodeExp(exp time.Duration) {
	m.codeExp = exp
}

// SetAuthorizeCodeTokenCfg set the authorization code grant token config
func (m *Manager) SetAuthorizeCodeTokenCfg(cfg *Config) {
	m.gtcfg[oauth2.AuthorizationCode] = cfg
}

// SetImplicitTokenCfg set the implicit grant token config
func (m *Manager) SetImplicitTokenCfg(cfg *Config) {
	m.gtcfg[oauth2.Implicit] = cfg
}

// SetPasswordTokenCfg set the password grant token config
func (m *Manager) SetPasswordTokenCfg(cfg *Config) {
	m.gtcfg[oauth2.PasswordCredentials] = cfg
}

// SetClientTokenCfg set the client grant token config
func (m *Manager) SetClientTokenCfg(cfg *Config) {
	m.gtcfg[oauth2.ClientCredentials] = cfg
}

// SetRefreshTokenCfg set the refreshing token config
func (m *Manager) SetRefreshTokenCfg(cfg *RefreshingConfig) {
	m.rcfg = cfg
}

// SetValidateURIHandler set the validates that RedirectURI is contained in baseURI
func (m *Manager) SetValidateURIHandler(handler ValidateURIHandler) {
	m.validateURI = handler
}

// MapTokenModel mapping the token information model
func (m *Manager) MapTokenModel(token oauth2.Token) {
	m.injector.Map(token)
}

// MapAuthorizeGenerate mapping the authorize code generate interface
func (m *Manager) MapAuthorizeGenerate(gen oauth2.AuthorizeGenerate) {
	m.injector.Map(gen)
}

// MapAccessGenerate mapping the access token generate interface
func (m *Manager) MapAccessGenerate(gen oauth2.AccessGenerate) {
	m.injector.Map(gen)
}

// MapClientStorage mapping the client store interface
func (m *Manager) MapClientStorage(stor oauth2.ClientStore) {
	m.injector.Map(stor)
}

// MustClientStorage mandatory mapping the client store interface
func (m *Manager) MustClientStorage(stor oauth2.ClientStore, err error) {
	if err != nil {
		panic(err.Error())
	}
	m.injector.Map(stor)
}

// MapUserStorage mapping the client store interface
func (m *Manager) MapUserStorage(stor oauth2.UserStore) {
	m.injector.Map(stor)
}

// MustUserStorage mandatory mapping the client store interface
func (m *Manager) MustUserStorage(stor oauth2.UserStore, err error) {
	if err != nil {
		panic(err.Error())
	}
	m.injector.Map(stor)
}

// MapTokenStorage mapping the token store interface
func (m *Manager) MapTokenStorage(stor oauth2.TokenStore) {
	m.injector.Map(stor)
}

// MustTokenStorage mandatory mapping the token store interface
func (m *Manager) MustTokenStorage(stor oauth2.TokenStore, err error) {
	if err != nil {
		panic(err)
	}
	m.injector.Map(stor)
}

// MapPasswordEncoder mapping the password encoder interface
func (m *Manager) MapPasswordEncoder(encoder oauth2.PasswordEncoder) {
	m.injector.Map(encoder)
}

// CheckInterface check the interface implementation
func (m *Manager) CheckInterface() error {
	_, err := m.injector.Invoke(func(
		oauth2.Token, oauth2.AccessGenerate, oauth2.TokenStore,
		oauth2.ClientStore, oauth2.AuthorizeGenerate,
	) {
	})
	return err
}

// GetClient get the client information
func (m *Manager) GetClient(clientID string) (cli oauth2.Client, err error) {
	_, ierr := m.injector.Invoke(func(stor oauth2.ClientStore) {
		cli, err = stor.GetByID(clientID)
		if err != nil {
			return
		} else if cli == nil {
			err = oauth2.ErrInvalidClient
		}
	})
	if err == nil && ierr != nil {
		err = ierr
	}
	return
}

// GenerateAuthToken generate the authorization token(code)
func (m *Manager) GenerateAuthToken(rt oauth2.ResponseType, tgr *oauth2.TokenGenerateRequest, cli oauth2.Client) (authToken oauth2.Token, err error) {
	if verr := m.validateURI(cli.GetRedirectUri(), tgr.RedirectURI); verr != nil {
		err = verr
		return
	}
	_, ierr := m.injector.Invoke(func(ti oauth2.Token, gen oauth2.AuthorizeGenerate, tgen oauth2.AccessGenerate, stor oauth2.TokenStore) {
		ti = ti.New()
		ti.SetClientID(tgr.ClientID)
		ti.SetUserID(tgr.UserID)
		ti.SetRedirectURI(tgr.RedirectURI)
		ti.SetScope(tgr.Scope)

		td := &oauth2.GenerateBasic{
			Client:   cli,
			UserID:   tgr.UserID,
			CreateAt: time.Now(),
			Token:    ti,
		}
		switch rt {
		case oauth2.CodeRsp:
			tv, terr := gen.Token(td)
			if terr != nil {
				err = terr
				return
			}
			ti.SetCode(tv)
			codeExp := m.codeExp
			if codeExp == 0 {
				codeExp = DefaultCodeExp
			}
			ti.SetCodeExpiresIn(codeExp)
			ti.SetCodeCreateAt(td.CreateAt)
			if exp := tgr.AccessTokenExp; exp > 0 {
				ti.SetAccessExpiresIn(exp)
			}
		case oauth2.TokenRsp:
			icfg := m.grantConfig(oauth2.Implicit)
			tv, rv, terr := tgen.Token(td, icfg.IsGenerateRefresh)
			if terr != nil {
				err = terr
				return
			}
			ti.SetAccess(tv)
			ti.SetAccessCreateAt(td.CreateAt)
			// set access token expires
			aexp := icfg.AccessTokenExp
			if exp := tgr.AccessTokenExp; exp > 0 {
				aexp = exp
			}
			ti.SetAccessExpiresIn(aexp)

			if rv != "" {
				ti.SetRefresh(rv)
				ti.SetRefreshCreateAt(td.CreateAt)
				ti.SetRefreshExpiresIn(icfg.RefreshTokenExp)
			}
		}

		err = stor.Create(ti)
		if err != nil {
			return
		}
		authToken = ti
	})
	if ierr != nil && err == nil {
		err = ierr
	}
	return
}

// get authorization code data
func (m *Manager) getAuthorizationCode(code string) (info oauth2.Token, err error) {
	_, ierr := m.injector.Invoke(func(stor oauth2.TokenStore) {
		ti, terr := stor.GetByCode(code)
		if terr != nil {
			err = terr
			return
		} else if ti == nil || ti.GetCode() != code || ti.GetCodeCreateAt().Add(ti.GetCodeExpiresIn()).Before(time.Now()) {
			err = oauth2.ErrInvalidAuthorizeCode
			return
		}
		info = ti
	})
	if ierr != nil && err == nil {
		err = ierr
	}
	return
}

// delete authorization code data
func (m *Manager) delAuthorizationCode(code string) (err error) {
	_, ierr := m.injector.Invoke(func(stor oauth2.TokenStore) {
		err = stor.RemoveByCode(code)
	})
	if ierr != nil && err == nil {
		err = ierr
	}
	return
}

// GenerateAccessToken generate the access token
func (m *Manager) GenerateAccessToken(gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest, cli oauth2.Client) (accessToken oauth2.Token, err error) {
	if gt == oauth2.AuthorizationCode {
		ti, terr := m.getAuthorizationCode(tgr.Code)
		if terr != nil {
			err = terr
			return
		} else if ti.GetRedirectURI() != tgr.RedirectURI || ti.GetClientID() != tgr.ClientID {
			err = oauth2.ErrInvalidAuthorizeCode
			return
		} else if verr := m.delAuthorizationCode(tgr.Code); verr != nil {
			err = verr
			return
		}
		tgr.UserID = ti.GetUserID()
		tgr.Scope = ti.GetScope()
		if exp := ti.GetAccessExpiresIn(); exp > 0 {
			tgr.AccessTokenExp = exp
		}
	}

	_, ierr := m.injector.Invoke(func(tokenDetails oauth2.Token, gen oauth2.AccessGenerate, stor oauth2.TokenStore) {
		// TODO. load existingAccessToken

		tokenDetails = tokenDetails.New()
		td := &oauth2.GenerateBasic{
			Client:   cli,
			UserID:   tgr.UserID,
			CreateAt: time.Now(),
			Token:    tokenDetails,
		}
		gcfg := m.grantConfig(gt)

		av, rv, terr := gen.Token(td, gcfg.IsGenerateRefresh)
		if terr != nil {
			err = terr
			return
		}
		tokenDetails.SetClientID(tgr.ClientID)
		tokenDetails.SetUserID(tgr.UserID)
		tokenDetails.SetRedirectURI(tgr.RedirectURI)
		tokenDetails.SetScope(tgr.Scope)
		tokenDetails.SetAccessCreateAt(td.CreateAt)
		tokenDetails.SetAccess(av)
		// set access token expires
		aexp := gcfg.AccessTokenExp
		if exp := tgr.AccessTokenExp; exp > 0 {
			aexp = exp
		}
		if exp := cli.GetAccessTokenExp(); exp > 0 {
			aexp = exp
		}
		tokenDetails.SetAccessExpiresIn(aexp)
		if rv != "" {
			tokenDetails.SetRefresh(rv)
			tokenDetails.SetRefreshCreateAt(td.CreateAt)
			// set refresh token expires
			rexp := gcfg.RefreshTokenExp
			if exp := cli.GetRefreshTokenExp(); exp > 0 {
				rexp = exp
			}
			tokenDetails.SetRefreshExpiresIn(rexp)
		}

		err = stor.Create(tokenDetails)
		if err != nil {
			return
		}
		accessToken = tokenDetails
	})
	if ierr != nil && err == nil {
		err = ierr
	}
	return
}

// RefreshAccessToken refreshing an access token
func (m *Manager) RefreshAccessToken(tgr *oauth2.TokenGenerateRequest) (accessToken oauth2.Token, err error) {
	cli, err := m.GetClient(tgr.ClientID)
	if err != nil {
		return
	} else if tgr.ClientSecret != cli.GetSecret() {
		err = oauth2.ErrInvalidClient
		return
	}

	ti, err := m.LoadRefreshToken(tgr.Refresh)
	if err != nil {
		return
	} else if ti.GetClientID() != tgr.ClientID {
		err = oauth2.ErrInvalidRefreshToken
		return
	}

	oldAccess, oldRefresh := ti.GetAccess(), ti.GetRefresh()
	_, ierr := m.injector.Invoke(func(stor oauth2.TokenStore, gen oauth2.AccessGenerate) {
		td := &oauth2.GenerateBasic{
			Client:   cli,
			UserID:   ti.GetUserID(),
			CreateAt: time.Now(),
			Token:    ti,
		}

		rcfg := DefaultRefreshTokenCfg
		if v := m.rcfg; v != nil {
			rcfg = v
		}

		tv, rv, terr := gen.Token(td, rcfg.IsGenerateRefresh)
		if terr != nil {
			err = terr
			return
		}

		ti.SetAccess(tv)
		ti.SetAccessCreateAt(td.CreateAt)

		if v := rcfg.AccessTokenExp; v > 0 {
			ti.SetAccessExpiresIn(v)
		}

		if v := rcfg.RefreshTokenExp; v > 0 {
			ti.SetRefreshExpiresIn(v)
		}

		if rcfg.IsResetRefreshTime {
			ti.SetRefreshCreateAt(td.CreateAt)
		}

		if scope := tgr.Scope; scope != "" {
			ti.SetScope(scope)
		}

		if rv != "" {
			ti.SetRefresh(rv)
		}

		if verr := stor.Create(ti); verr != nil {
			err = verr
			return
		}

		if rcfg.IsRemoveAccess {
			// remove the old access token
			if verr := stor.RemoveByAccess(oldAccess); verr != nil {
				err = verr
				return
			}
		}

		if rcfg.IsRemoveRefreshing && rv != "" {
			// remove the old refresh token
			if verr := stor.RemoveByRefresh(oldRefresh); verr != nil {
				err = verr
				return
			}
		}

		accessToken = ti

		if rv == "" {
			accessToken.SetRefresh("")
			accessToken.SetRefreshCreateAt(time.Now())
			accessToken.SetRefreshExpiresIn(0)
		}
	})
	if ierr != nil && err == nil {
		err = ierr
	}
	return
}

// RemoveAccessToken use the access token to delete the token information
func (m *Manager) RemoveAccessToken(access string) (err error) {
	if access == "" {
		err = oauth2.ErrInvalidAccessToken
		return
	}
	_, ierr := m.injector.Invoke(func(stor oauth2.TokenStore) {
		err = stor.RemoveByAccess(access)
	})
	if ierr != nil && err == nil {
		err = ierr
	}
	return
}

// RemoveRefreshToken use the refresh token to delete the token information
func (m *Manager) RemoveRefreshToken(refresh string) (err error) {
	if refresh == "" {
		err = oauth2.ErrInvalidAccessToken
		return
	}
	_, ierr := m.injector.Invoke(func(stor oauth2.TokenStore) {
		err = stor.RemoveByRefresh(refresh)
	})
	if ierr != nil && err == nil {
		err = ierr
	}
	return
}

// LoadAccessToken according to the access token for corresponding token information
func (m *Manager) LoadAccessToken(access string) (info oauth2.Token, err error) {
	if access == "" {
		err = oauth2.ErrInvalidAccessToken
		return
	}
	_, ierr := m.injector.Invoke(func(stor oauth2.TokenStore) {
		ct := time.Now()
		ti, terr := stor.GetByAccess(access)
		if terr != nil {
			err = terr
			return
		} else if ti == nil || ti.GetAccess() != access {
			err = oauth2.ErrInvalidAccessToken
			return
		} else if ti.GetRefresh() != "" && ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(ct) {
			err = oauth2.ErrExpiredRefreshToken
		} else if ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Before(ct) {
			err = oauth2.ErrExpiredAccessToken
			return
		}
		info = ti
	})
	if ierr != nil && err == nil {
		err = ierr
	}
	return
}

// LoadRefreshToken according to the refresh token for corresponding token information
func (m *Manager) LoadRefreshToken(refresh string) (info oauth2.Token, err error) {
	if refresh == "" {
		err = oauth2.ErrInvalidRefreshToken
		return
	}
	_, ierr := m.injector.Invoke(func(stor oauth2.TokenStore) {
		ti, terr := stor.GetByRefresh(refresh)
		if terr != nil {
			err = terr
			return
		} else if ti == nil || ti.GetRefresh() != refresh {
			err = oauth2.ErrInvalidRefreshToken
			return
		} else if ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(time.Now()) {
			err = oauth2.ErrExpiredRefreshToken
			return
		}
		info = ti
	})
	if ierr != nil && err == nil {
		err = ierr
	}
	return
}
