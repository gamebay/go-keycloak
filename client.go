package keycloak

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v8"
)

type Client struct {
	sync.RWMutex
	gocloak gocloak.GoCloak
	ctx     context.Context
	token   *gocloak.JWT
	Addr    string
	Realm   string
	Client  string
	Secret  string
}

func New(addr string, realm string, client string, secret string) (*Client, error) {
	ctx := context.Background()

	gc := gocloak.NewClient(addr)
	token, err := gc.LoginClient(ctx, client, secret, realm)
	if err != nil {
		return nil, err
	}

	c := &Client{
		gocloak: gc,
		ctx:     ctx,
		token:   token,
		Addr:    addr,
		Realm:   realm,
		Client:  client,
		Secret:  secret,
	}
	go c.refresh()

	return c, nil
}

func (c *Client) refresh() {
	accessTicker := time.NewTicker(time.Second * time.Duration(c.token.ExpiresIn-285))
	refreshTicker := time.NewTicker(time.Second * time.Duration(c.token.RefreshExpiresIn-10))

	for {
		select {
		case <-accessTicker.C:
			if err := c.Refresh(); err != nil {
				log.Println(err)
			}
		case <-refreshTicker.C:
			if err := c.Login(); err != nil {
				log.Println(err)
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) Login() error {
	c.Lock()
	defer c.Unlock()

	token, err := c.gocloak.LoginClient(c.ctx, c.Client, c.Secret, c.Realm)
	if err != nil {
		return err
	}

	log.Println("login")
	c.token = token

	return nil
}

func (c *Client) Refresh() error {
	c.Lock()
	defer c.Unlock()

	token, err := c.gocloak.RefreshToken(c.ctx, c.token.RefreshToken, c.Client, c.Secret, c.Realm)
	if err != nil {
		return err
	}

	log.Println("refresh")
	c.token = token

	return nil
}
