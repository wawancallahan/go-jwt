package config

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	LOGIN_EXPIRATION_DURATION = time.Duration(1) * time.Hour
	JWT_SIGNING_METHOD        = jwt.SigningMethodHS256
	JWT_SIGNATURE_KEY         = []byte("SECRET JWT")
)

type JwtClaims struct {
	jwt.RegisteredClaims

	UserName string `json:"user_name"`
}

func GenerateJwtToken() string {
	claims := JwtClaims{
		UserName: "USER",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "APP_NAME",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(LOGIN_EXPIRATION_DURATION)),
		},
	}

	token := jwt.NewWithClaims(JWT_SIGNING_METHOD, claims)

	signedToken, err := token.SignedString(JWT_SIGNATURE_KEY)

	if err != nil {
		log.Fatal("Couldn't create token", err)
	}

	return signedToken
}

func ValidateJwtTokenClaims(tokenString string) (*JwtClaims, error) {
	claims := &JwtClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Signing method invalid")
		} else if method != JWT_SIGNING_METHOD {
			return nil, fmt.Errorf("Signing method invalid")
		}

		return JWT_SIGNATURE_KEY, nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}

func ValidateJwtTokenMap(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Signing method invalid")
		} else if method != JWT_SIGNING_METHOD {
			return nil, fmt.Errorf("Signing method invalid")
		}

		return JWT_SIGNATURE_KEY, nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil || !token.Valid {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}

	return &claims, nil
}

func MiddlewareJWTAuthorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authorizationHeader := r.Header.Get("Authorization")
		if !strings.Contains(authorizationHeader, "Bearer") {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)

		var claims JwtClaims

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Signing method invalid")
			} else if method != JWT_SIGNING_METHOD {
				return nil, fmt.Errorf("Signing method invalid")
			}

			return JWT_SIGNATURE_KEY, nil
		})

		// token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 	if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		// 		return nil, fmt.Errorf("Signing method invalid")
		// 	} else if method != JWT_SIGNING_METHOD {
		// 		return nil, fmt.Errorf("Signing method invalid")
		// 	}

		// 	return JWT_SIGNATURE_KEY, nil
		// })
		if err != nil || !token.Valid {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// claims, ok := token.Claims.(JwtClaims)
		// if !ok || !token.Valid {
		// 	http.Error(w, err.Error(), http.StatusBadRequest)
		// 	return
		// }

		ctx := context.WithValue(context.Background(), "userInfo", claims)
		r = r.WithContext(ctx)

		// How to Get Value From Local Context
		// userInfo := r.Context().Value("userInfo").(JwtClaims)
	})
}
