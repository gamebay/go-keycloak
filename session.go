package keycloak

import "github.com/Nerzal/gocloak/v8"

type Session struct {
	token *gocloak.JWT
}

func (s *Session) SetToken(token *gocloak.JWT) {
	s.token = token
}

func (s *Session) GetAccessToken() string {
	return s.token.AccessToken
}

func (s *Session) GetRefreshToken() string {
	return s.token.RefreshToken
}
