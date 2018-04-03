package main

import (
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/hexagon-cloud/oauth2"
	"github.com/hexagon-cloud/oauth2/manager"
	"github.com/hexagon-cloud/oauth2/server"
	buntdbStore "github.com/hexagon-cloud/oauth2/store/buntdb"
	memoryStore "github.com/hexagon-cloud/oauth2/store/memory"
	session "gopkg.in/session.v1"
	"time"
)

var (
	globalSessions *session.Manager
)

func init() {
	globalSessions, _ = session.NewManager("memory", `{"cookieName":"gosessionid","gclifetime":3600}`)
	go globalSessions.GC()
}

func main() {
	mgr := manager.NewDefaultManager()
	// token store
	mgr.MustTokenStorage(buntdbStore.NewMemoryTokenStore())

	clientStore := memoryStore.NewClientStore()
	clientStore.Set("server", &oauth2.Client{
		ID:                   "server",
		Secret:               "server",
		Domain:               "http://localhost:9094",
		Scopes:               []string{"server"},
		AuthorizedGrantTypes: []oauth2.GrantType{oauth2.ClientCredentials},
		AccessTokenExp:       time.Duration(8)*time.Hour,
		RefreshTokenExp:      time.Duration(8)*time.Hour,
	})
	mgr.MapClientStorage(clientStore)

	uaaServer := server.NewServer(server.NewConfig(), mgr)
	uaaServer.SetUserAuthorizationHandler(userAuthorizeHandler)

	uaaServer.SetInternalErrorHandler(func(err error) (re *oauth2.ErrorResponse) {
		log.Println("Internal Error:", err.Error())
		return
	})

	uaaServer.SetResponseErrorHandler(func(re *oauth2.ErrorResponse) {
		log.Println("ErrorResponse Error:", re.Error.Error())
	})

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/auth", authHandler)

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := uaaServer.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := uaaServer.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Println("Server is running at 8401 port.")
	log.Fatal(http.ListenAndServe(":8401", nil))
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	us, err := globalSessions.SessionStart(w, r)
	uid := us.Get("UserID")
	if uid == nil {
		if r.Form == nil {
			r.ParseForm()
		}
		us.Set("Form", r.Form)
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	userID = uid.(string)
	us.Delete("UserID")
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		us, err := globalSessions.SessionStart(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		us.Set("LoggedInUserID", "000000")
		w.Header().Set("Location", "/auth")
		w.WriteHeader(http.StatusFound)
		return
	}
	outputHTML(w, r, "static/login.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	us, err := globalSessions.SessionStart(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if us.Get("LoggedInUserID") == nil {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}
	if r.Method == "POST" {
		form := us.Get("Form").(url.Values)
		u := new(url.URL)
		u.Path = "/authorize"
		u.RawQuery = form.Encode()
		w.Header().Set("Location", u.String())
		w.WriteHeader(http.StatusFound)
		us.Delete("Form")
		us.Set("UserID", us.Get("LoggedInUserID"))
		return
	}
	outputHTML(w, r, "static/auth.html")
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}
