package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

func Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := FromAuthHeader(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		claims, err := DecodeAccessToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		username, ok := claims["preferred_username"]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "username", username)))
	})
}

func FromAuthHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("invalid token")
	}

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", fmt.Errorf("authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}
