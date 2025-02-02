package token

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rsa"
	"e_commerce/auth/server/config"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"strings"
	"time"
)

const (
	AccessToken  = "access_token"
	RefreshToken = "refresh_token"
)

type AuthClaim struct {
	UserId string
	Type   string
	jwt.StandardClaims
}

func GenerateToken(userId string, prvKey *rsa.PrivateKey) (string, string, error) {
	nowTime := time.Now()
	claims := AuthClaim{
		UserId: userId,
		Type:   AccessToken,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  nowTime.Unix(),
			Issuer:    "AuthService",
			NotBefore: nowTime.Unix(),
			ExpiresAt: nowTime.Add(config.AccessTokenExpTime).Unix(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessTokenStr, err := accessToken.SignedString(prvKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	claims.Type = RefreshToken
	claims.StandardClaims.ExpiresAt = nowTime.Add(config.RefreshTokenExpTime).Unix()
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	refreshTokenStr, err := refreshToken.SignedString(prvKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	tokenHash := getMD5Hash(refreshTokenStr)
	_, err = redisClient.Set(context.Background(), tokenHash, 1, config.RefreshTokenExpTime).Result()
	if err != nil {
		return "", "", fmt.Errorf("failed to save refresh token to database: %w", err)
	}

	return accessTokenStr, refreshTokenStr, nil
}

func GetClaimsFromToken(token string) (*AuthClaim, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token contains an invalid number of segments")
	}

	var claimBytes []byte
	var err error
	if claimBytes, err = jwt.DecodeSegment(parts[1]); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))

	authClaim := &AuthClaim{}
	err = dec.Decode(authClaim)
	// Handle decode error
	if err != nil {
		return nil, err
	}

	return authClaim, nil
}

func VerifyAccessToken(pubKey *rsa.PublicKey, tokenStr string) error {
	claims, err := parseToken(pubKey, tokenStr)
	if err != nil {
		return fmt.Errorf("failed to parse access token: %w", err)
	}

	if claims.Type != AccessToken {
		return fmt.Errorf("unsupproted token type: %s", claims.Type)
	}

	return nil
}

func VerifyRefreshToken(pubKey *rsa.PublicKey, tokenStr string) error {
	claims, err := parseToken(pubKey, tokenStr)
	if err != nil {
		return fmt.Errorf("failed to parse refresh token: %w", err)
	}

	if claims.Type != RefreshToken {
		return fmt.Errorf("unsupproted token type: %s", claims.Type)
	}

	hashValue := getMD5Hash(tokenStr)
	result, err := redisClient.Del(context.Background(), hashValue).Result()
	if err != nil {
		return fmt.Errorf("failed to delete refresh token from database: %w", err)
	}

	if result == 0 {
		return fmt.Errorf("refresh token %s has been used", tokenStr)
	}

	return nil
}

func getMD5Hash(tokenStr string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(tokenStr)))
}

func parseToken(pubKey *rsa.PublicKey, tokenStr string) (*AuthClaim, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AuthClaim{}, func(jwtToken *jwt.Token) (interface{}, error) {
		if jwtToken.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unsupported signature method: %s", jwtToken.Method.Alg())
		}
		return pubKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AuthClaim); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token: %v", tokenStr)
	}
}
