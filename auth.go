package keycloak

import (
	"errors"
)

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

func (c *Client) LoginUser(username string, password string) (*Token, error) {
	jwt, err := c.gocloak.Login(c.ctx, c.Client, c.Secret, c.Realm, username, password)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	token := parseToken(jwt)
	return token, nil
}

func (c *Client) LogoutUser(refresh string) error {
	err := c.gocloak.Logout(c.ctx, c.Client, c.Secret, c.Realm, refresh)
	if err != nil {
		return ErrInvalidRefreshToken
	}

	return nil
}

func (c *Client) RefreshUser(refresh string) (*Token, error) {
	jwt, err := c.gocloak.RefreshToken(c.ctx, refresh, c.Client, c.Secret, c.Realm)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	token := parseToken(jwt)
	return token, nil
}

func (c *Client) InspectUser() error {
	return nil
}
