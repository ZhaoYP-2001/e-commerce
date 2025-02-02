package token

import (
	"bou.ke/monkey"
	"fmt"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
)

func TestPrvKey(t *testing.T) {
	storedPrvKeyMap := sync.Map{}
	monkey.Patch(CreatePrvKey, func(userId string, prvKey string) error {
		storedPrvKeyMap.Store(userId, prvKey)
		return nil
	})
	defer monkey.Unpatch(CreatePrvKey)

	monkey.Patch(QueryPrvKey, func(userId string) (string, error) {
		if prvKey, ok := storedPrvKeyMap.Load(userId); ok {
			return prvKey.(string), nil
		} else {
			return "", fmt.Errorf("no secret key for user %s", userId)
		}
	})
	defer monkey.Unpatch(QueryPrvKey)

	user_id := "test_user"
	prvKey, err := NewPrvKey(user_id)
	if err != nil {
		t.Error(err)
	}
	outputPrvKey, err := LoadPrvKey(user_id)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, prvKey, outputPrvKey)

	newPrvKey, err := NewPrvKey(user_id)
	if err != nil {
		t.Error(err)
	}
	err = SavePrvKey(user_id, newPrvKey)
	if err != nil {
		t.Error(err)
	}
	outputPrvKey, err = LoadPrvKey(user_id)
	assert.Equal(t, newPrvKey, outputPrvKey)
}
