package keycloak

import (
	"fmt"

	"github.com/Nerzal/gocloak/v8"
	"github.com/lestrrat-go/jwx/jwt"
)

type Token struct {
	IDToken          string `json:"id_token"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

func parseToken(jwt *gocloak.JWT) *Token {
	return &Token{
		IDToken:          jwt.IDToken,
		AccessToken:      jwt.AccessToken,
		ExpiresIn:        jwt.ExpiresIn,
		RefreshToken:     jwt.RefreshToken,
		RefreshExpiresIn: jwt.RefreshExpiresIn,
		TokenType:        jwt.TokenType,
		NotBeforePolicy:  jwt.NotBeforePolicy,
		SessionState:     jwt.SessionState,
		Scope:            jwt.Scope,
	}
}

func DecodeAccessToken(token string) (map[string]interface{}, error) {
	p, err := jwt.Parse([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	return p.PrivateClaims(), nil
}
