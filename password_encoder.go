package oauth2

type PasswordEncoder interface {
	Encode(rawPassword string) string
	Matches(rawPassword string, encodedPassword string) bool
}
