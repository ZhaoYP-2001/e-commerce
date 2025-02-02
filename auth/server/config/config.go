package config

import "time"

const (
	AccessTokenExpTime  = time.Hour
	RefreshTokenExpTime = time.Hour * 24 * 3
)
const (
	RSAKeyBits = 2048
)

const (
	ServerAddr = "localhost:9091"
)

const (
	MySQLDSN      = "root:123456@tcp(dn:3306)/auth?charset=utf8mb4&parseTime=True&loc=Local"
	RedisAddr     = "dn:6379"
	RedisPassword = "123456"
)
