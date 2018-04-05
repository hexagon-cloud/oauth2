package memory

import (
	"testing"

	"github.com/hexagon-cloud/oauth2"

)

func TestClientStore(t *testing.T) {
	Convey("Test client store", t, func() {
		clientStore := NewClientStore()

		err := clientStore.Set("1", &oauth2.DefaultClient{ID: "1", Secret: "2"})
		So(err, ShouldBeNil)

		cli, err := clientStore.GetByID("1")
		So(err, ShouldBeNil)
		So(cli.GetID(), ShouldEqual, "1")
	})
}
