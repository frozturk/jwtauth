package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/twinj/uuid"
)

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
}

var JWTSECRET string
var redisClient *redis.Client

func Setup(jwtsecret string, redisclient *redis.Client) {
	JWTSECRET = jwtsecret
	redisClient = redisclient
}

func CreateToken(userid uint64) (*TokenDetails, error) {
	user_id := strconv.FormatUint(userid, 10)
	token_uuid := uuid.NewV4().String()

	accessToken, err := generateTokenHMAC(token_uuid, user_id, true)
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateTokenHMAC(token_uuid, user_id, false)
	if err != nil {
		return nil, err
	}

	td := &TokenDetails{AccessToken: accessToken, RefreshToken: refreshToken}
	return td, nil
}

func LogoutToken(r *http.Request) error {
	accessToken, err := extractAccessToken(r)
	if err != nil {
		return err
	}
	if !accessToken.Valid {
		return fmt.Errorf("invalid access token")
	}

	accessTokenClaims, err := getStandardClaims(accessToken)
	if err != nil {
		return err
	}
	blacklistTime := time.Unix(accessTokenClaims.ExpiresAt, 0).Add(time.Hour * 24 * 7).Unix()
	err = blacklistToken(accessTokenClaims.Id, accessTokenClaims.Subject, blacklistTime)
	return err
}

func RefreshTokens(r *http.Request) (*TokenDetails, error) {
	accessToken, err := extractAccessToken(r)
	if err != nil {
		vErr, ok := err.(*jwt.ValidationError)
		if ok {
			if vErr.Errors != jwt.ValidationErrorExpired {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if accessToken.Valid {
		return nil, fmt.Errorf("access token is already valid")
	}
	refreshToken, err := extractRefreshToken(r)
	if err != nil {
		return nil, err
	}

	accessTokenClaims, err := getStandardClaims(accessToken)
	if err != nil {
		return nil, err
	}
	refreshTokenClaims, err := getStandardClaims(refreshToken)
	if err != nil {
		return nil, err
	}
	if accessTokenClaims.Id != refreshTokenClaims.Id {
		return nil, fmt.Errorf("token mismatch")
	}

	if checkBlacklist(accessTokenClaims.Id) {
		return nil, fmt.Errorf("unauthenticated")
	}

	err = blacklistToken(refreshTokenClaims.Id, refreshTokenClaims.Subject, refreshTokenClaims.ExpiresAt)
	if err != nil {
		return nil, err
	}

	userid, err := strconv.ParseUint(refreshTokenClaims.Subject, 10, 64)
	if err != nil {
		return nil, err
	}
	return CreateToken(userid)

}

func IsAuthenticated(r *http.Request) error {
	accessToken, err := extractAccessToken(r)
	if err != nil {
		return err
	}
	if _, ok := accessToken.Claims.(jwt.Claims); !ok || !accessToken.Valid {
		return err
	}
	accessTokenClaims, err := getStandardClaims(accessToken)
	if err != nil {
		return err
	}
	if checkBlacklist(accessTokenClaims.Id) {
		return fmt.Errorf("unauthenticated")
	}
	return nil
}

func generateTokenHMAC(token_uuid string, user_id string, isAccessToken bool) (string, error) {
	claims := jwt.StandardClaims{}
	claims.Id = token_uuid
	claims.Subject = user_id
	if isAccessToken {
		claims.ExpiresAt = time.Now().Add(time.Minute * 15).Unix()
	} else {
		claims.ExpiresAt = time.Now().Add(time.Hour * 24 * 7).Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(JWTSECRET))
	if err != nil {
		return "", err
	}

	return signedToken, nil

}

func blacklistToken(token_uuid string, user_id string, exp int64) error {
	expTime := time.Unix(exp, 0)
	now := time.Now()
	ctx := context.Background()
	err := redisClient.Set(ctx, token_uuid, user_id, expTime.Sub(now)).Err()
	if err != nil {
		return err
	}
	return nil
}

func checkBlacklist(token_uuid string) bool {
	ctx := context.Background()
	_, err := redisClient.Get(ctx, token_uuid).Result()
	return err == nil
}

func parseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(JWTSECRET), nil
	})
	return token, err
}

func extractAccessToken(r *http.Request) (*jwt.Token, error) {
	accessTokenString, err := extractAccessTokenString(r)
	if err != nil {
		return nil, err
	}
	accessToken, err := parseToken(accessTokenString)
	if err != nil {
		return accessToken, err
	}
	return accessToken, nil
}

func extractRefreshToken(r *http.Request) (*jwt.Token, error) {
	refreshTokenString, err := extractRefreshTokenString(r)
	if err != nil {
		return nil, err
	}
	refreshToken, err := parseToken(refreshTokenString)
	if err != nil {
		return nil, err
	}
	return refreshToken, nil
}
func extractAccessTokenString(r *http.Request) (string, error) {
	bearerToken := r.Header.Get("Authorization")
	token := strings.Split(bearerToken, " ")
	if len(token) == 2 {
		return token[1], nil
	}
	return "", fmt.Errorf("no authorization header")
}

func extractRefreshTokenString(r *http.Request) (string, error) {
	reqBody := map[string]string{}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&reqBody); err != nil {
		return "", err
	}
	refreshToken, exist := reqBody["refresh_token"]
	if !exist {
		return "", fmt.Errorf("no refresh token in request")
	}
	return refreshToken, nil
}

func getStandardClaims(token *jwt.Token) (*jwt.StandardClaims, error) {
	stdClaims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil, fmt.Errorf("unknown token")
	}
	return stdClaims, nil
}
