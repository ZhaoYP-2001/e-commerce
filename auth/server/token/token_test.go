package token

import (
	"bou.ke/monkey"
	"context"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
	"time"
)

func TestAccessToken(t *testing.T) {
	redisInstance := make(map[string]int64)
	monkey.PatchInstanceMethod(
		reflect.TypeOf(redis.Client{}), "Set",
		func(client redis.Client, ctx context.Context, key string, val interface{}, expiration time.Duration) *redis.StatusCmd {
			redisInstance[key] = time.Now().Add(expiration).Unix()
			cmd := &redis.StatusCmd{}
			cmd.SetVal("1")
			return cmd
		})

	monkey.PatchInstanceMethod(
		reflect.TypeOf(redis.Client{}), "Del", func(client redis.Client, ctx context.Context, keys ...string) *redis.IntCmd {
			cmd := &redis.IntCmd{}
			if expirationTime, ok := redisInstance[keys[0]]; ok {
				delete(redisInstance, keys[0])
				if expirationTime > time.Now().Unix() {
					cmd.SetVal(1)
					return cmd
				}
			}
			cmd.SetErr(redis.Nil)
			cmd.SetVal(1)
			return cmd
		},
	)
	defer monkey.UnpatchAll()

	prvKey, err := genRsaKey(2048)
	if err != nil {
		t.Error(err)
	}

	userId := "userId"
	accessToken, _, err := GenerateToken(userId, prvKey)
	if err != nil {
		t.Error(err)
	}

	outClaims, err := GetClaimsFromToken(accessToken)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, userId, outClaims.UserId)
	assert.Equal(t, AccessToken, outClaims.Type)

	err = VerifyAccessToken(&prvKey.PublicKey, accessToken)
	assert.Equal(t, nil, err)
}

func TestRefreshToken(t *testing.T) {
	redisInstance := make(map[string]int64)
	monkey.PatchInstanceMethod(
		reflect.TypeOf(redis.Client{}), "Set",
		func(client redis.Client, ctx context.Context, key string, val interface{}, expiration time.Duration) *redis.StatusCmd {
			redisInstance[key] = time.Now().Add(expiration).Unix()
			cmd := &redis.StatusCmd{}
			cmd.SetVal("1")
			return cmd
		})

	monkey.PatchInstanceMethod(
		reflect.TypeOf(redis.Client{}), "Del", func(client redis.Client, ctx context.Context, keys ...string) *redis.IntCmd {
			cmd := &redis.IntCmd{}
			if expirationTime, ok := redisInstance[keys[0]]; ok {
				delete(redisInstance, keys[0])
				if expirationTime > time.Now().Unix() {
					cmd.SetVal(1)
					return cmd
				}
			}
			cmd.SetErr(redis.Nil)
			cmd.SetVal(1)
			return cmd
		},
	)
	defer monkey.UnpatchAll()

	prvKey, err := genRsaKey(2048)
	if err != nil {
		t.Error(err)
	}

	_, refreshToken, err := GenerateToken("userId", prvKey)
	if err != nil {
		t.Error(err)
	}

	err = VerifyRefreshToken(&prvKey.PublicKey, refreshToken)
	assert.Equal(t, nil, err)

	assert.Equal(t, 0, len(redisInstance))
}
