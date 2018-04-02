// The golang oauth2 service implementation, compatible with spring cloud oauth2.
//
//     package main
//     import (
//         "net/http"
//         "github.com/hexagon-cloud/oauth2/manager"
//         "github.com/hexagon-cloud/oauth2/server"
//         buntdbStore "github.com/hexagon-cloud/oauth2/store/buntdb"
//         memoryStore "github.com/hexagon-cloud/oauth2/store/memory"
//     )
//     func main() {
//         mgr := manager.NewDefaultManager()
//         mgr.MustTokenStorage(buntdbStore.NewMemoryTokenStore())
//         mgr.MapClientStorage(memoryStore.NewClientStore())
//         srv := server.NewDefaultServer(manager)
//         http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
//             srv.HandleAuthorizeRequest(w, r)
//         })
//         http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
//             srv.HandleTokenRequest(w, r)
//         })
//         http.ListenAndServe(":8401", nil)
//     }

package oauth2
