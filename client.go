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
	gc     gocloak.GoCloak
	ctx    context.Context
	Token  *gocloak.JWT
	Addr   string
	Realm  string
	Client string
	Secret string
}

func New(addr string, realm string, client string, secret string) (*Client, error) {
	ctx := context.Background()

	gc := gocloak.NewClient(addr)
	token, err := gc.LoginClient(ctx, client, secret, realm)
	if err != nil {
		return nil, err
	}

	c := &Client{
		gc:     gc,
		ctx:    ctx,
		Token:  token,
		Addr:   addr,
		Realm:  realm,
		Client: client,
		Secret: secret,
	}
	go c.startRefresh()

	return c, nil
}

func (c *Client) startRefresh() {
	for {
		c.RLock()
		refreshTicker := time.NewTicker(time.Second * time.Duration(c.Token.ExpiresIn-5))
		c.RUnlock()

		select {
		case <-refreshTicker.C:
			if err := c.refresh(); err != nil {
				log.Println(err)
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) refresh() error {
	c.RLock()
	token, err := c.gc.RefreshToken(c.ctx, c.Token.RefreshToken, c.Client, c.Secret, c.Realm)
	c.RUnlock()
	if err != nil {
		return err
	}

	c.Lock()
	c.Token = token
	c.Unlock()

	return nil
}
