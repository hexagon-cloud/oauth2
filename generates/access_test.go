package generates_test

import (
	"testing"
	"time"

	"github.com/hexagon-cloud/oauth2"
	"github.com/hexagon-cloud/oauth2/generates"

)

func TestAccess(t *testing.T) {
	Convey("Test Access Generate", t, func() {
		data := &oauth2.GenerateBasic{
			Client: &oauth2.DefaultClient{
				ID:     "123456",
				Secret: "123456",
			},
			UserID:   "000000",
			CreateAt: time.Now(),
		}
		gen := generates.NewAccessGenerate()
		access, refresh, err := gen.Token(data, true)
		So(err, ShouldBeNil)
		So(access, ShouldNotBeEmpty)
		So(refresh, ShouldNotBeEmpty)
		Println("\nAccess DefaultToken:" + access)
		Println("Refresh DefaultToken:" + refresh)
	})
}
