package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v8"
)

type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func (c *Client) ListUsers() ([]*User, error) {
	var users []*User

	var params gocloak.GetUsersParams
	kusers, err := c.gocloak.GetUsers(context.Background(), c.token.AccessToken, c.Realm, params)
	if err != nil {
		return users, err
	}

	for _, user := range kusers {
		users = append(users, parseUser(user))
	}

	return users, nil
}

func (c *Client) CreateUser(username string, password string, email string, firstName string, lastName string) (string, error) {
	emailVerified := true
	passwordTemporary := false

	u := gocloak.User{
		Username:      &username,
		Email:         &email,
		FirstName:     &firstName,
		LastName:      &lastName,
		EmailVerified: &emailVerified,
	}

	id, err := c.gocloak.CreateUser(context.Background(), c.token.AccessToken, c.Realm, u)
	if err != nil {
		return "", err
	}

	err = c.gocloak.SetPassword(context.Background(), c.token.AccessToken, id, c.Realm, password, passwordTemporary)
	if err != nil {
		return "", err
	}

	return id, nil
}

func (c *Client) GetUser(id string) (*User, error) {
	kuser, err := c.gocloak.GetUserByID(context.Background(), c.token.AccessToken, c.Realm, id)
	if err != nil {
		return nil, err
	}

	user := parseUser(kuser)
	return user, nil
}

func (c *Client) UpdateUser(id string, username string, email string, firstName string, lastName string) error {
	user := gocloak.User{
		ID:        &id,
		Username:  &username,
		Email:     &email,
		FirstName: &firstName,
		LastName:  &lastName,
	}

	err := c.gocloak.UpdateUser(context.Background(), c.token.AccessToken, c.Realm, user)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) DeleteUser(id string) error {
	err := c.gocloak.DeleteUser(context.Background(), c.token.AccessToken, c.Realm, id)
	if err != nil {
		return err
	}

	return nil
}

func parseUser(user *gocloak.User) *User {
	return &User{
		ID:        *user.ID,
		Username:  *user.Username,
		Email:     *user.Email,
		FirstName: *user.FirstName,
		LastName:  *user.LastName,
	}
}
