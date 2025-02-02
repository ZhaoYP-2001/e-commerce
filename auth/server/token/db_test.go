package token

import (
	"e_commerce/auth/server/config"
	"errors"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"testing"
)

func TestMySQLDB(t *testing.T) {
	initDB(config.MySQLDSN)
	user_id := "test_user"
	originPrvKey := "test_prv_key"

	err := createPrvKey(user_id, originPrvKey)
	if err != nil {
		t.Error(err)
	}
	outputPrvKey, err := queryPrvKey(user_id)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, originPrvKey, outputPrvKey)

	// primary key conflict
	createNewPrvKey := "test_create_prv_key"
	err = createPrvKey(user_id, createNewPrvKey)
	if err != nil {
		t.Error(err)
	}
	outputPrvKey, err = queryPrvKey(user_id)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, createNewPrvKey, outputPrvKey)

	updateNewPrvKey := "test_update_prv_key"
	err = updatePrvKey(user_id, updateNewPrvKey)
	if err != nil {
		t.Error(err)
	}
	outputPrvKey, err = queryPrvKey(user_id)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, updateNewPrvKey, outputPrvKey)

	err = deletePrvKey(user_id)
	if err != nil {
		t.Error(err)
	}
	_, err = queryPrvKey(user_id)
	assert.Equal(t, errors.Is(err, gorm.ErrRecordNotFound), true)
}
