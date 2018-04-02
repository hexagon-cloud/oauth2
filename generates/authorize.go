package generates

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/hexagon-cloud/oauth2"
	"github.com/satori/go.uuid"
)

// NewAuthorizeGenerate create to generate the authorize code instance
func NewAuthorizeGenerate() *AuthorizeGenerate {
	return &AuthorizeGenerate{}
}

// AuthorizeGenerate generate the authorize code
type AuthorizeGenerate struct{}

// Token based on the UUID generated token
func (ag *AuthorizeGenerate) Token(data *oauth2.GenerateBasic) (code string, err error) {
	buf := bytes.NewBufferString(data.Client.GetID())
	buf.WriteString(data.UserID)
	token := uuid.NewV3(uuid.Must(uuid.NewV1()), buf.String())
	code = base64.URLEncoding.EncodeToString(token.Bytes())
	code = strings.ToUpper(strings.TrimRight(code, "="))

	return
}
