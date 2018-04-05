package manager

import (
	"testing"

	"github.com/hexagon-cloud/oauth2"
	"github.com/hexagon-cloud/oauth2/manager"
	"github.com/hexagon-cloud/oauth2/store/buntdb"
	"github.com/hexagon-cloud/oauth2/store/memory"

)

func TestManager(t *testing.T) {
	Convey("Manager test", t, func() {
		manager := manager.NewDefaultManager()

		manager.MustTokenStorage(buntdb.NewMemoryTokenStore())

		clientStore := memory.NewMemoryClientStore()
		clientStore.Set("1", &oauth2.DefaultClient{
			ID:          "1",
			Secret:      "11",
			RedirectUri: "http://localhost",
		})
		manager.MapClientStorage(clientStore)

		tgr := &oauth2.TokenGenerateRequest{
			ClientID:    "1",
			UserID:      "123456",
			RedirectURI: "http://localhost/oauth2",
			Scope:       "all",
		}

		Convey("CheckInterface test", func() {
			err := manager.CheckInterface()
			So(err, ShouldBeNil)
		})

		Convey("GetClient test", func() {
			cli, err := manager.GetClient("1")
			So(err, ShouldBeNil)
			So(cli.GetSecret(), ShouldEqual, "11")
		})

		Convey("DefaultToken test", func() {
			testManager(tgr, manager)
		})
	})
}

func testManager(tgr *oauth2.TokenGenerateRequest, manager oauth2.Manager) {
	cti, err := manager.GenerateAuthToken(oauth2.CodeRsp, tgr)
	So(err, ShouldBeNil)

	code := cti.GetCode()
	So(code, ShouldNotBeEmpty)

	atParams := &oauth2.TokenGenerateRequest{
		ClientID:     tgr.ClientID,
		ClientSecret: "11",
		RedirectURI:  tgr.RedirectURI,
		Code:         code,
	}
	ati, err := manager.GenerateAccessToken(oauth2.AuthorizationCode, atParams)
	So(err, ShouldBeNil)

	accessToken, refreshToken := ati.GetAccess(), ati.GetRefresh()
	So(accessToken, ShouldNotBeEmpty)
	So(refreshToken, ShouldNotBeEmpty)

	ainfo, err := manager.LoadAccessToken(accessToken)
	So(err, ShouldBeNil)
	So(ainfo.GetClientID(), ShouldEqual, atParams.ClientID)

	arinfo, err := manager.LoadRefreshToken(accessToken)
	So(err, ShouldNotBeNil)
	So(arinfo, ShouldBeNil)

	rainfo, err := manager.LoadAccessToken(refreshToken)
	So(err, ShouldNotBeNil)
	So(rainfo, ShouldBeNil)

	rinfo, err := manager.LoadRefreshToken(refreshToken)
	So(err, ShouldBeNil)
	So(rinfo.GetClientID(), ShouldEqual, atParams.ClientID)

	atParams.Refresh = refreshToken
	atParams.Scope = "owner"
	rti, err := manager.RefreshAccessToken(atParams)
	So(err, ShouldBeNil)

	refreshAT := rti.GetAccess()
	So(refreshAT, ShouldNotBeEmpty)

	_, err = manager.LoadAccessToken(accessToken)
	So(err, ShouldNotBeNil)

	refreshAInfo, err := manager.LoadAccessToken(refreshAT)
	So(err, ShouldBeNil)
	So(refreshAInfo.GetScope(), ShouldEqual, "owner")

	err = manager.RemoveAccessToken(refreshAT)
	So(err, ShouldBeNil)

	_, err = manager.LoadAccessToken(refreshAT)
	So(err, ShouldNotBeNil)

	err = manager.RemoveRefreshToken(refreshToken)
	So(err, ShouldBeNil)

	_, err = manager.LoadRefreshToken(refreshToken)
	So(err, ShouldNotBeNil)
}
