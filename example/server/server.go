package main

import (
	"log"
	"net/http"
	"github.com/hexagon-cloud/oauth2"
	"github.com/hexagon-cloud/oauth2/manager"
	"github.com/hexagon-cloud/oauth2/server"
	buntdbStore "github.com/hexagon-cloud/oauth2/store/buntdb"
	memoryStore "github.com/hexagon-cloud/oauth2/store/memory"
	"time"
	"github.com/hexagon-cloud/oauth2/passoword/sha256"
)

func main() {
	mgr := manager.NewDefaultManager()
	// token store
	mgr.MustTokenStorage(buntdbStore.NewMemoryTokenStore())

	clientStore := memoryStore.NewClientStore()
	clientStore.Set("server", &oauth2.Client{
		ID:                   "server",
		Secret:               "server",
		Domain:               "http://localhost:8080",
		Scopes:               []string{"server", "all"},
		AuthorizedGrantTypes: []oauth2.GrantType{oauth2.ClientCredentials},
		AccessTokenExp:       time.Duration(8) * time.Hour,
		RefreshTokenExp:      time.Duration(8) * time.Hour,
	})
	clientStore.Set("app", &oauth2.Client{
		ID:                   "app",
		Secret:               "app",
		Scopes:               []string{"app"},
		AuthorizedGrantTypes: []oauth2.GrantType{oauth2.PasswordCredentials},
		AccessTokenExp:       time.Duration(8) * time.Hour,
		RefreshTokenExp:      time.Duration(8) * time.Hour,
	})
	mgr.MapClientStorage(clientStore)

	pwdEncoder := sha256.NewPasswordEncoder("key")
	mgr.MapPasswordEncoder(pwdEncoder)

	userStore := memoryStore.NewUserStore()
	userStore.Set("user1", &oauth2.User{
		Username: "user1",
		Password: pwdEncoder.Encode("pwd1"),
	})
	mgr.MapUserStorage(userStore)

	uaaServer := server.NewServer(server.NewConfig(), mgr)

	uaaServer.SetInternalErrorHandler(func(err error) (re *oauth2.ErrorResponse) {
		log.Println("Internal Error:", err.Error())
		return
	})

	uaaServer.SetResponseErrorHandler(func(re *oauth2.ErrorResponse) {
		log.Println("ErrorResponse Error:", re.Error.Error())
	})

	http.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := uaaServer.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		err := uaaServer.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Println("Server is running at 8401 port.")
	log.Fatal(http.ListenAndServe(":8401", nil))
}
