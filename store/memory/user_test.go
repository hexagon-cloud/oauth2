package memory

import (
	"testing"

	"github.com/hexagon-cloud/oauth2"

)

func TestUserStore(t *testing.T) {
	Convey("Test user store", t, func() {
		userStore := NewUserStore()

		err := userStore.Set("user", &oauth2.DefaultUser{Username: "user", Password: "pwd"})
		So(err, ShouldBeNil)

		user, err := userStore.GetByUsername("user")
		So(err, ShouldBeNil)
		So(user.GetUsername(), ShouldEqual, "user")
	})
}
