package token

import (
	"context"
	"e_commerce/auth/server/config"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/plugin/soft_delete"
	"time"
)

var db *gorm.DB
var redisClient *redis.Client

func init() {
	initDB(config.MySQLDSN)
	initRedis(config.RedisAddr, config.RedisPassword)
}

func initDB(dsn string) {
	var err error
	db, err = gorm.Open(mysql.Open(dsn))
	if err != nil {
		panic(err)
	}
	err = db.AutoMigrate(&PreKey{})
	if err != nil {
		panic(err)
	}
}

func initRedis(addr string, password string) {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0,
	})
	pong, err := redisClient.Ping(context.Background()).Result()
	if err != nil {
		panic(err)
	}
	if pong != "PONG" {
		panic(fmt.Errorf("unexpected reply to ping redis: %s", pong))
	}
}

type PreKey struct {
	UserId    string `gorm:"primaryKey"`
	PrvKey    string
	CreatedAt time.Time
	DeletedAt time.Time             `gorm:"default:Null"`
	IsDel     soft_delete.DeletedAt `gorm:"softDelete:flag,DeletedAtField:DeletedAt"`
}

func (prvKey *PreKey) TableName() string {
	return "private_key"
}

func createPrvKey(userId string, prvKey string) error {
	if userId == "" || prvKey == "" {
		return errors.New("user-id and private key should not be empty")
	}
	result := db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&PreKey{UserId: userId, PrvKey: prvKey})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func deletePrvKey(userId string) error {
	result := db.Delete(&PreKey{UserId: userId})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func updatePrvKey(userId string, prvKey string) error {
	if userId == "" || prvKey == "" {
		return errors.New("user-id and private key should not be empty")
	}
	result := db.Model(&PreKey{UserId: userId}).Updates(&PreKey{PrvKey: prvKey})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func queryPrvKey(userId string) (string, error) {
	prvKey := &PreKey{UserId: userId}
	result := db.First(prvKey)
	if result.Error != nil {
		return "", result.Error
	}
	return prvKey.PrvKey, nil
}
